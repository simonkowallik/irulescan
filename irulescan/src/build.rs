fn main() {
    // Tell cargo to tell rustc to link the lib tcl-irulescan
    println!("cargo:rustc-link-lib=tcl-irulescan");

    // The bindgen::Builder is the main entry point
    // to bindgen, and lets you build up options for
    // the resulting bindings.
    let bindings = bindgen::Builder::default()
        // The input header we would like to generate
        // bindings for.
        .header("src/mytcl.h")
        // Suppress warnings
        .raw_line("#![allow(unnecessary_transmutes)]")
        // Finish the builder and generate the bindings.
        .generate()
        // Unwrap the Result and panic on failure.
        .expect("Unable to generate bindings");

    bindings
        .write_to_file("src/tcl.rs")
        .expect("Couldn't write bindings!");
}
