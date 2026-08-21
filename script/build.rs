fn main() {
    println!("cargo:rerun-if-env-changed=SKIP_SP1_BUILD");
    #[cfg(feature = "sp1")]
    {
        if std::env::var("SKIP_SP1_BUILD").ok().as_deref() != Some("1") {
            sp1_build::build_program("../program");
        }
    }
}
