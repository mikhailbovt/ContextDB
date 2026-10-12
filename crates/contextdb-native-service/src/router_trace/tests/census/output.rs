//! Explicit fresh output of the fixed public native fixture.

use super::*;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Artifact {
    bytes: u64,
    digest: ContentDigest,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Manifest {
    format: String,
    generator: String,
    feature_schema: String,
    digest_algorithm: String,
    public_synthetic: bool,
    sizing_only: bool,
    private_intake: bool,
    accepted_model_request: bool,
    model_inference: bool,
    lineage_scope: String,
    partition: String,
    cases: u32,
    rows: u32,
    artifacts: BTreeMap<String, Artifact>,
}

fn artifact(data: &[u8], budget: &mut QueryBudget) -> Result<Artifact> {
    charge(budget, data.len() as u64 / 4096 + 1, 0)?;
    Ok(Artifact {
        bytes: data.len() as u64,
        digest: ContentDigest::from_bytes(*blake3::hash(data).as_bytes()),
    })
}

pub(super) fn fresh_root(root: &Path) -> Result<()> {
    if !root.is_absolute()
        || root.components().count() > 32
        || root.try_exists().map_err(|_| invalid())?
    {
        return Err(invalid());
    }
    let parent = root.parent().ok_or_else(invalid)?;
    if !parent.is_dir() {
        return Err(invalid());
    }
    for ancestor in parent.ancestors() {
        let metadata = fs::symlink_metadata(ancestor).map_err(|_| invalid())?;
        let name = ancestor
            .file_name()
            .and_then(|name| name.to_str())
            .unwrap_or_default();
        if metadata.file_type().is_symlink()
            || !metadata.is_dir()
            || name.ends_with(".fjall")
            || name.ends_with(".native-fjall")
            || name.starts_with("owned-native-kev-gate-")
            || (ancestor.join("keyspaces").is_dir() && ancestor.join("version").is_file())
        {
            return Err(invalid());
        }
    }
    // The supplied root must be isolated from an existing owned archive host.
    for (index, entry) in fs::read_dir(parent).map_err(|_| invalid())?.enumerate() {
        if index >= 4096 {
            return Err(invalid());
        }
        let entry = entry.map_err(|_| invalid())?;
        let name = entry.file_name();
        let name = name.to_str().ok_or_else(invalid)?;
        if name.ends_with(".native-profile.json") || name.ends_with(".ctxb") {
            return Err(invalid());
        }
    }
    Ok(())
}

fn write_new(root: &Path, name: &str, data: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(root.join(name))
        .map_err(|_| invalid())?;
    file.write_all(data).map_err(|_| invalid())?;
    file.sync_all().map_err(|_| invalid())
}

pub(super) fn export(
    root: &Path,
    corpus: &Corpus,
    budget: &mut QueryBudget,
) -> Result<ContentDigest> {
    charge(budget, 8192, 0)?;
    fresh_root(root)?;
    validate(corpus, budget)?;
    let inputs = bytes(&corpus.inputs, MAX_CORPUS, budget)?;
    let observations = bytes(&corpus.observations, MAX_CORPUS, budget)?;
    if inputs.len().saturating_add(observations.len()) > MAX_CORPUS {
        return Err(invalid());
    }
    let manifest = Manifest {
        format: FORMAT.into(),
        generator: GENERATOR.into(),
        feature_schema: SEMANTIC_SCORING_FEATURE_SCHEMA.into(),
        digest_algorithm: "blake3-256".into(),
        public_synthetic: true,
        sizing_only: true,
        private_intake: false,
        accepted_model_request: false,
        model_inference: false,
        lineage_scope: LINEAGE.into(),
        partition: "train".into(),
        cases: corpus.observations.cases.len() as u32,
        rows: corpus.inputs.len() as u32,
        artifacts: BTreeMap::from([
            ("inputs.json".into(), artifact(&inputs, budget)?),
            ("observations.json".into(), artifact(&observations, budget)?),
        ]),
    };
    let manifest_bytes = bytes(&manifest, 64 * 1024, budget)?;
    if inputs
        .len()
        .saturating_add(observations.len())
        .saturating_add(manifest_bytes.len())
        > MAX_CORPUS
    {
        return Err(invalid());
    }
    let digest = artifact(&manifest_bytes, budget)?.digest;
    charge(
        budget,
        3,
        (inputs.len() + observations.len() + manifest_bytes.len()) as u64,
    )?;
    fs::create_dir(root).map_err(|_| invalid())?;
    write_new(root, "inputs.json", &inputs)?;
    write_new(root, "observations.json", &observations)?;
    // Completion witness last; incomplete output is never resumed or accepted.
    write_new(root, "manifest.json", &manifest_bytes)?;
    // A successful generating gate also validates the stored bytes and cold
    // structure. The external CPU intake can pin all three files with SHA256
    // after this BLAKE3/score-join proof, without adding a Python dependency.
    let stored_manifest = read_output(&root.join("manifest.json"), manifest_bytes.len(), budget)?;
    let stored_inputs = read_output(&root.join("inputs.json"), inputs.len(), budget)?;
    let stored_observations =
        read_output(&root.join("observations.json"), observations.len(), budget)?;
    if stored_manifest != manifest_bytes
        || stored_inputs != inputs
        || stored_observations != observations
        || artifact(&stored_manifest, budget)?.digest != digest
    {
        return Err(invalid());
    }
    let stored: Manifest = serde_json::from_slice(&stored_manifest).map_err(|_| invalid())?;
    for (name, data) in [
        ("inputs.json", &stored_inputs),
        ("observations.json", &stored_observations),
    ] {
        let expected = stored.artifacts.get(name).ok_or_else(invalid)?;
        let actual = artifact(data, budget)?;
        if actual.bytes != expected.bytes || actual.digest != expected.digest {
            return Err(invalid());
        }
    }
    charge(
        budget,
        1,
        ((stored_inputs.len() + stored_observations.len()) as u64).saturating_mul(2),
    )?;
    let cold = Corpus {
        inputs: serde_json::from_slice(&stored_inputs).map_err(|_| invalid())?,
        observations: serde_json::from_slice(&stored_observations).map_err(|_| invalid())?,
    };
    validate(&cold, budget)?;
    Ok(digest)
}

fn read_output(path: &Path, exact_bytes: usize, budget: &mut QueryBudget) -> Result<Vec<u8>> {
    if exact_bytes > MAX_CORPUS {
        return Err(invalid());
    }
    charge(budget, 1, (exact_bytes as u64).saturating_mul(2))?;
    let metadata = fs::symlink_metadata(path).map_err(|_| invalid())?;
    if metadata.file_type().is_symlink()
        || !metadata.is_file()
        || metadata.len() != exact_bytes as u64
    {
        return Err(invalid());
    }
    let file = fs::File::open(path).map_err(|_| invalid())?;
    let mut result = Vec::new();
    file.take(exact_bytes as u64 + 1)
        .read_to_end(&mut result)
        .map_err(|_| invalid())?;
    if result.len() != exact_bytes {
        return Err(invalid());
    }
    Ok(result)
}
