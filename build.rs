use std::process::Command;

fn main() {
    // Re-run only when these files change; avoids rebuilding on every cargo invocation.
    for path in &[
        "ui/src/editor.js",
        "ui/src/graph.js",
        "ui/src/nft-language.js",
        "ui/package.json",
        "ui/vite.config.js",
    ] {
        println!("cargo:rerun-if-changed={path}");
    }

    // Allow CI environments without npm to skip the JS build (bundles are committed).
    if std::env::var("SKIP_JS_BUILD").is_ok() {
        return;
    }

    let ui = "ui";

    let status = Command::new("npm")
        .args(["install", "--user-agent", "fwgui-build"])
        .current_dir(ui)
        .status()
        .expect("build.rs: npm not found — install Node.js to build JS assets");
    assert!(status.success(), "build.rs: npm install failed");

    let status = Command::new("npm")
        .args(["run", "build"])
        .current_dir(ui)
        .status()
        .expect("build.rs: npm run build failed to start");
    assert!(status.success(), "build.rs: npm run build failed");
}
