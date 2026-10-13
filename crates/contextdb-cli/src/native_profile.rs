//! Explicit native custody selection, pinned outside the restoreable database.

use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use contextdb_core::ObservationId;
use contextdb_native_service::{
    CustodyMasterKey, NativeCustodyKeys, NativeService, NativeSuppressionLedger,
};
use contextdb_service::{CognitiveMemoryService, ErrorCode, ServiceError, VerifyRequest};
use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;

use crate::{CliError, CliResult, LoadedState, TokenKey, codex_service, state_head};

pub(crate) const ENCRYPTED_PROFILE: &str = "codex-native-encrypted-custody-v1";
pub(crate) const MASTER_KEY_ENV: &str = "CONTEXTDB_NATIVE_MASTER_KEY_HEX";
const MAX_PROFILE_BYTES: u64 = 16 * 1024;

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BrokerProfile {
    pub(crate) profile: String,
    pub(crate) digest: Option<String>,
}

impl BrokerProfile {
    pub(crate) fn plain() -> Self {
        Self {
            profile: "codex-local-hybrid-v1".to_owned(),
            digest: None,
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct CustodyIdentity {
    pub(crate) database_id: String,
    pub(crate) custody_authority: ObservationId,
    pub(crate) suppression_authority: ObservationId,
    pub(crate) custody_format: u16,
    pub(crate) suppression_format: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Descriptor {
    schema_version: u16,
    profile: String,
    identity: CustodyIdentity,
    archive_path: String,
    native_path: String,
    custody_root: String,
}

#[derive(Clone, Copy, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum InitializationState {
    Initializing,
    Ready,
    RestorePending,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct ProfileFile {
    descriptor: Descriptor,
    state: InitializationState,
    master_key_tag: String,
    token_mac: String,
}

#[derive(Serialize)]
struct UnsignedProfile<'a> {
    descriptor: &'a Descriptor,
    state: InitializationState,
    master_key_tag: &'a str,
}

pub(crate) struct NativeProfile {
    file: ProfileFile,
    digest: String,
    master: Zeroizing<[u8; 32]>,
}

impl std::fmt::Debug for NativeProfile {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("NativeProfile")
            .field("profile", &ENCRYPTED_PROFILE)
            .finish_non_exhaustive()
    }
}

pub(crate) fn profile_path(path: &Path) -> PathBuf {
    let mut name = path.as_os_str().to_owned();
    name.push(".native-profile.json");
    PathBuf::from(name)
}

fn error(message: &'static str) -> CliError {
    ServiceError::new(ErrorCode::IntegrityFailure, message, false).into()
}

fn encode(value: &impl Serialize) -> CliResult<Vec<u8>> {
    serde_json::to_vec(value).map_err(|_| error("native profile encoding failed"))
}

fn profile_bytes(file: &ProfileFile) -> CliResult<Vec<u8>> {
    let bytes = encode(file)?;
    // Reserve room for later state names without accepting an unreadable intent.
    if bytes.len() > MAX_PROFILE_BYTES as usize - 32 {
        return Err(error("native profile exceeds its bounded format"));
    }
    Ok(bytes)
}

fn digest(descriptor: &Descriptor) -> CliResult<String> {
    Ok(blake3::hash(&encode(descriptor)?).to_hex().to_string())
}

fn tag(key: &[u8; 32], domain: &str, bytes: &[u8]) -> String {
    let derived = Zeroizing::new(blake3::derive_key(domain, key));
    blake3::keyed_hash(&derived, bytes).to_hex().to_string()
}

fn hash_eq(actual: &str, expected: &str) -> bool {
    match (
        blake3::Hash::from_hex(actual),
        blake3::Hash::from_hex(expected),
    ) {
        (Ok(actual), Ok(expected)) => actual == expected,
        _ => false,
    }
}

fn token_mac(file: &ProfileFile, key: &TokenKey) -> CliResult<String> {
    Ok(tag(
        &key.expose_copy(),
        "contextdb/cli/native-profile-token/v1",
        &encode(&UnsignedProfile {
            descriptor: &file.descriptor,
            state: file.state,
            master_key_tag: &file.master_key_tag,
        })?,
    ))
}

fn read_master(key: &TokenKey) -> CliResult<Zeroizing<[u8; 32]>> {
    let encoded = std::env::var(MASTER_KEY_ENV)
        .map(Zeroizing::new)
        .map_err(|_| {
            error("native master key is required through CONTEXTDB_NATIVE_MASTER_KEY_HEX")
        })?;
    if encoded.len() != 64 {
        return Err(error(
            "native master key must contain 64 hexadecimal characters",
        ));
    }
    let mut master = Zeroizing::new([0_u8; 32]);
    for (index, pair) in encoded.as_bytes().chunks_exact(2).enumerate() {
        let high = crate::decode_hex_nibble(pair[0])
            .ok_or_else(|| error("native master key is not hexadecimal"))?;
        let low = crate::decode_hex_nibble(pair[1])
            .ok_or_else(|| error("native master key is not hexadecimal"))?;
        master[index] = (high << 4) | low;
    }
    if master.iter().all(|byte| *byte == 0)
        || blake3::hash(master.as_ref()) == blake3::hash(&key.expose_copy())
    {
        return Err(error(
            "native custody requires a nonzero master key distinct from the token key",
        ));
    }
    Ok(master)
}

fn path_string(path: &Path) -> CliResult<String> {
    path.to_str()
        .map(ToOwned::to_owned)
        .ok_or_else(|| error("native profile requires Unicode paths"))
}

fn exists(path: &Path) -> CliResult<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(_) => Err(error("native profile destination cannot be inspected")),
    }
}

fn validate_paths(descriptor: &Descriptor, path: &Path, existing: bool) -> CliResult<()> {
    let canonical = state_head::canonical_archive_path(path)
        .map_err(|_| error("native lifecycle path is unavailable"))?;
    let native = codex_service::native_store_path(&canonical);
    if descriptor.archive_path != path_string(&canonical)?
        || descriptor.native_path != path_string(&native)?
    {
        return Err(error(
            "native profile belongs to another lifecycle or native path",
        ));
    }
    let root = Path::new(&descriptor.custody_root);
    let parent = canonical
        .parent()
        .ok_or_else(|| error("native lifecycle parent is unavailable"))?;
    if !root.is_absolute()
        || root.starts_with(parent)
        || parent.starts_with(root)
        || root.starts_with(&native)
        || native.starts_with(root)
    {
        return Err(error(
            "native custody root must be separate from the database directory",
        ));
    }
    let root_parent = root
        .parent()
        .ok_or_else(|| error("native custody root parent is unavailable"))?;
    crate::reject_custody_path_links(root_parent, "native custody parent")
        .map_err(|_| error("native custody parent is unavailable or linked"))?;
    let resolved_parent =
        fs::canonicalize(root_parent).map_err(|_| error("native custody parent is unavailable"))?;
    if resolved_parent.join(
        root.file_name()
            .ok_or_else(|| error("native custody root must name a directory"))?,
    ) != root
    {
        return Err(error("native custody root is not canonical"));
    }
    if existing {
        for required in [
            root.to_path_buf(),
            root.join("keys"),
            root.join("suppression"),
        ] {
            if crate::canonical_custody_directory(&required, "native custody authority")
                .map_err(|_| error("current native custody authority is unavailable or linked"))?
                != required
            {
                return Err(error("current native custody authority path differs"));
            }
        }
        for authority in [root.join("keys"), root.join("suppression")] {
            contextdb_storage_fjall::FjallStorage::check_existing_controls(&authority)
                .map_err(|_| error("current native custody controls are unavailable"))?;
        }
    }
    Ok(())
}

fn read_file(path: &Path) -> CliResult<ProfileFile> {
    crate::reject_custody_path_links(path, "native profile")
        .map_err(|_| error("native profile is unavailable or linked"))?;
    let file = fs::File::open(path).map_err(|_| error("native profile is unavailable"))?;
    let metadata = file
        .metadata()
        .map_err(|_| error("native profile is unavailable"))?;
    if !metadata.is_file() || metadata.len() > MAX_PROFILE_BYTES {
        return Err(error("native profile exceeds its bounded format"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_PROFILE_BYTES + 1)
        .read_to_end(&mut bytes)
        .map_err(|_| error("native profile read failed"))?;
    if bytes.len() > MAX_PROFILE_BYTES as usize {
        return Err(error("native profile exceeds its bounded format"));
    }
    serde_json::from_slice(&bytes).map_err(|_| error("native profile is invalid"))
}

pub(crate) fn load(
    path: &Path,
    key: &TokenKey,
    expected: Option<&str>,
) -> CliResult<Option<NativeProfile>> {
    let file_path = profile_path(path);
    let Some(expected) = expected else {
        if exists(&file_path)? {
            return Err(error("native profile lacks its external commitment"));
        }
        return Ok(None);
    };
    let file = read_file(&file_path)?;
    if file.descriptor.schema_version != 1
        || file.descriptor.profile != ENCRYPTED_PROFILE
        || file.descriptor.identity.custody_format != 4
        || file.descriptor.identity.suppression_format != 3
        || !hash_eq(&digest(&file.descriptor)?, expected)
        || !hash_eq(&token_mac(&file, key)?, &file.token_mac)
    {
        return Err(error(
            "native profile authentication or external binding failed",
        ));
    }
    match file.state {
        InitializationState::Initializing => {
            return Err(error(
                "native initialization is incomplete; explicit operator recovery is required",
            ));
        }
        InitializationState::RestorePending => {
            return Err(error(
                "native restoration is incomplete; explicit operator recovery is required",
            ));
        }
        InitializationState::Ready => {}
    }
    let master = read_master(key)?;
    if !hash_eq(
        &tag(
            &master,
            "contextdb/cli/native-profile-master/v1",
            &encode(&file.descriptor)?,
        ),
        &file.master_key_tag,
    ) {
        return Err(error("native profile master authentication failed"));
    }
    validate_paths(&file.descriptor, path, true)?;
    Ok(Some(NativeProfile {
        file,
        digest: expected.to_owned(),
        master,
    }))
}

pub(crate) fn probe(path: &Path, key: &TokenKey, reference: bool) -> CliResult<BrokerProfile> {
    state_head::StateHeadStore::probe_native_restore_ready(path, &key.expose_copy())
        .map_err(CliError::from)?;
    let expected =
        state_head::StateHeadStore::probe_native_profile_digest(path, &key.expose_copy())
            .map_err(CliError::from)?;
    let profile = load(path, key, expected.as_deref())?;
    if let Some(profile) = &profile {
        profile.require_native_existing()?;
    }
    if reference && profile.is_some() {
        return Err(error(
            "reference MCP mode cannot bypass the configured native custody profile",
        ));
    }
    Ok(profile
        .as_ref()
        .map_or_else(BrokerProfile::plain, NativeProfile::broker_profile))
}

/// Shutdown needs the token authority and immutable profile binding, so a lost
/// master/profile cannot prevent the operator from quiescing a running owner.
pub(crate) fn shutdown_profile(path: &Path, key: &TokenKey) -> CliResult<BrokerProfile> {
    let digest = state_head::StateHeadStore::probe_native_profile_digest(path, &key.expose_copy())
        .map_err(CliError::from)?;
    Ok(match digest {
        Some(digest) => BrokerProfile {
            profile: ENCRYPTED_PROFILE.to_owned(),
            digest: Some(digest),
        },
        None => BrokerProfile::plain(),
    })
}

impl NativeProfile {
    fn require_native_existing(&self) -> CliResult<()> {
        let native = Path::new(&self.file.descriptor.native_path);
        if crate::canonical_custody_directory(native, "native memory")
            .map_err(|_| error("current native memory is unavailable or linked"))?
            != native
        {
            return Err(error("current native memory path differs from its profile"));
        }
        contextdb_storage_fjall::FjallStorage::check_existing_controls(native)
            .map_err(|_| error("current native memory controls are unavailable"))?;
        Ok(())
    }
    pub(crate) fn broker_profile(&self) -> BrokerProfile {
        BrokerProfile {
            profile: ENCRYPTED_PROFILE.to_owned(),
            digest: Some(self.digest.clone()),
        }
    }
    pub(crate) fn identity(&self) -> &CustodyIdentity {
        &self.file.descriptor.identity
    }
    pub(crate) fn begin_restore(&mut self, token: &TokenKey) -> CliResult<()> {
        self.set_state(InitializationState::RestorePending, token)
    }
    pub(crate) fn finish_restore(&mut self, token: &TokenKey) -> CliResult<()> {
        self.set_state(InitializationState::Ready, token)
    }
    fn set_state(&mut self, state: InitializationState, token: &TokenKey) -> CliResult<()> {
        self.file.state = state;
        self.file.token_mac = token_mac(&self.file, token)?;
        crate::atomic_write(
            &profile_path(Path::new(&self.file.descriptor.archive_path)),
            &profile_bytes(&self.file)?,
            true,
        )
        .map_err(|_| {
            error(
                "native recovery state publication failed; explicit operator recovery is required",
            )
        })
    }
    pub(crate) fn open(&self, token: &TokenKey, create: bool) -> CliResult<NativeService> {
        let descriptor = &self.file.descriptor;
        if create {
            if self.file.state != InitializationState::RestorePending {
                return Err(error(
                    "native recovery requires its retained pending intent",
                ));
            }
            if exists(Path::new(&descriptor.native_path))? {
                return Err(error("native recovery requires a fresh pristine target"));
            }
        } else {
            self.require_native_existing()?;
        }
        let root = Path::new(&descriptor.custody_root);
        let ledger = NativeSuppressionLedger::open(
            root.join("suppression"),
            &descriptor.identity.database_id,
            descriptor.identity.suppression_authority.as_uuid(),
        )?;
        let keys = NativeCustodyKeys::open(
            root.join("keys"),
            &descriptor.identity.database_id,
            descriptor.identity.custody_authority.as_uuid(),
            CustodyMasterKey::from_zeroizing(Zeroizing::new(*self.master))?,
        )?;
        if keys.format_version() != 4 || ledger.format_version() != 3 {
            return Err(error(
                "native authority format differs from its pinned profile",
            ));
        }
        if create {
            Ok(NativeService::open_encrypted(
                &descriptor.native_path,
                &descriptor.identity.database_id,
                token.expose_copy(),
                ledger,
                keys,
            )?)
        } else {
            Ok(NativeService::open_encrypted_existing(
                &descriptor.native_path,
                &descriptor.identity.database_id,
                token.expose_copy(),
                ledger,
                keys,
            )?)
        }
    }
}

#[derive(Serialize)]
pub(crate) struct InitializationReceipt {
    pub(crate) operation: &'static str,
    pub(crate) profile: &'static str,
    pub(crate) profile_digest: String,
    pub(crate) custody_authority: ObservationId,
    pub(crate) suppression_authority: ObservationId,
}

pub(crate) fn initialize(
    path: &Path,
    root: &Path,
    state: &Arc<LoadedState>,
) -> CliResult<InitializationReceipt> {
    let key = &state.key;
    state
        .authority
        .require_native_restore_ready(&key.expose_copy())
        .map_err(CliError::from)?;
    let (_, identity) = state
        .authority
        .load_verified(&key.expose_copy())
        .map_err(CliError::from)?;
    if state
        .authority
        .native_profile_digest(&key.expose_copy())
        .map_err(CliError::from)?
        .is_some()
    {
        return Err(error(
            "native profile is already pinned; interrupted initialization requires explicit recovery",
        ));
    }
    let canonical = state_head::canonical_archive_path(path).map_err(CliError::from)?;
    let root_parent = root
        .parent()
        .filter(|_| root.is_absolute())
        .ok_or_else(|| error("native custody root must be absolute"))?;
    crate::reject_custody_path_links(root_parent, "native custody parent")
        .map_err(|_| error("native custody parent is unavailable or linked"))?;
    let root = fs::canonicalize(root_parent)
        .map_err(|_| error("native custody parent is unavailable"))?
        .join(
            root.file_name()
                .ok_or_else(|| error("native custody root must name a directory"))?,
        );
    for target in [
        root.clone(),
        codex_service::native_store_path(&canonical),
        profile_path(&canonical),
    ] {
        if exists(&target)? {
            return Err(error(
                "native initialization requires fresh custody, native and profile destinations; plaintext migration is separate",
            ));
        }
    }
    let descriptor = Descriptor {
        schema_version: 1,
        profile: ENCRYPTED_PROFILE.to_owned(),
        identity: CustodyIdentity {
            database_id: identity.database_id,
            custody_authority: ObservationId::new(),
            suppression_authority: ObservationId::new(),
            custody_format: 4,
            suppression_format: 3,
        },
        archive_path: path_string(&canonical)?,
        native_path: path_string(&codex_service::native_store_path(&canonical))?,
        custody_root: path_string(&root)?,
    };
    validate_paths(&descriptor, &canonical, false)?;
    let master = read_master(key)?;
    let commitment = digest(&descriptor)?;
    let mut file = ProfileFile {
        master_key_tag: tag(
            &master,
            "contextdb/cli/native-profile-master/v1",
            &encode(&descriptor)?,
        ),
        descriptor,
        state: InitializationState::Initializing,
        token_mac: String::new(),
    };
    file.token_mac = token_mac(&file, key)?;
    // Retain the exact descriptor before the one-way pin; neither operation
    // creates native values, keys or a replacement suppression authority.
    crate::atomic_write(&profile_path(&canonical), &profile_bytes(&file)?, false).map_err(|_| {
        error(
            "native profile intent could not be persisted; explicit operator recovery is required",
        )
    })?;
    state
        .authority
        .pin_native_profile(&key.expose_copy(), &commitment)
        .map_err(CliError::from)?;
    fs::create_dir(&root).map_err(|_| {
        error("native custody root creation failed; explicit operator recovery is required")
    })?;
    let ledger = NativeSuppressionLedger::create_with_authority(
        root.join("suppression"),
        &file.descriptor.identity.database_id,
        file.descriptor.identity.suppression_authority.as_uuid(),
    )?;
    let keys = NativeCustodyKeys::create_with_authority(
        root.join("keys"),
        &file.descriptor.identity.database_id,
        file.descriptor.identity.custody_authority.as_uuid(),
        CustodyMasterKey::from_zeroizing(Zeroizing::new(*master))?,
    )?;
    let native = NativeService::open_encrypted(
        &file.descriptor.native_path,
        &file.descriptor.identity.database_id,
        key.expose_copy(),
        ledger,
        keys,
    )?;
    native.verify(VerifyRequest {
        context: crate::codex_operator_authority(key, "codex-native-init")?.request,
        deep: true,
    })?;
    drop(native);
    file.state = InitializationState::Ready;
    file.token_mac = token_mac(&file, key)?;
    crate::atomic_write(&profile_path(&canonical), &profile_bytes(&file)?, true).map_err(|_| {
        error("native profile activation failed; explicit operator recovery is required")
    })?;
    Ok(InitializationReceipt {
        operation: "codex_native_initialized",
        profile: ENCRYPTED_PROFILE,
        profile_digest: commitment,
        custody_authority: file.descriptor.identity.custody_authority,
        suppression_authority: file.descriptor.identity.suppression_authority,
    })
}
