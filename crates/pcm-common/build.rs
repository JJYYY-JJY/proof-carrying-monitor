fn main() -> Result<(), Box<dyn std::error::Error>> {
    tonic_build::configure()
        .build_server(true)
        .build_client(true)
        .compile_protos(
            &[
                "../../proto/pcm/v1/types.proto",
                "../../proto/pcm/v1/services.proto",
            ],
            &["../../proto"],
        )?;
    Ok(())
}
