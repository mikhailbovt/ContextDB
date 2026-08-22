use std::error::Error;
use std::path::PathBuf;

fn main() -> Result<(), Box<dyn Error>> {
    let schema = PathBuf::from("proto/contextdb/v1/contextdb.proto");
    let include = PathBuf::from("proto");
    let protoc = protoc_bin_vendored::protoc_bin_path()?;

    let mut prost = tonic_prost_build::Config::new();
    prost.protoc_executable(protoc);
    prost.btree_map([".contextdb.v1"]);
    prost.enable_type_names();

    tonic_prost_build::configure()
        .build_client(cfg!(feature = "grpc"))
        .build_server(cfg!(feature = "grpc"))
        .codec_path("crate::BoundedProstCodec")
        .file_descriptor_set_path(PathBuf::from(std::env::var("OUT_DIR")?).join("contextdb-v1.bin"))
        .compile_with_config(prost, &[schema], &[include])?;

    Ok(())
}
