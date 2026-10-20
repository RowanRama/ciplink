//! On macOS a Python extension module leaves the interpreter's symbols to be resolved when it is imported; the
//! linker has to be told to allow that (`-undefined dynamic_lookup`). PyO3 adds the right arguments per platform.
fn main() {
    pyo3_build_config::add_extension_module_link_args();
}
