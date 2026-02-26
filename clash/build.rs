use std::process::Command;

fn main() {
    if let Some(hash) = git_hash() {
        println!("cargo:rustc-env=CLASH_GIT_HASH={hash}");
    }

    // Rerun when HEAD or any ref changes
    println!("cargo:rerun-if-changed=../.git/HEAD");
    println!("cargo:rerun-if-changed=../.git/refs/");
}

fn git_hash() -> Option<String> {
    let output = Command::new("git")
        .args(["rev-parse", "--short", "HEAD"])
        .output()
        .ok()?;

    if !output.status.success() {
        return None;
    }

    let hash = String::from_utf8_lossy(&output.stdout).trim().to_string();
    if hash.is_empty() {
        return None;
    }

    let dirty = Command::new("git")
        .args(["status", "--porcelain"])
        .output()
        .ok()
        .is_some_and(|o| !o.stdout.is_empty());

    if dirty {
        Some(format!("{hash}-dirty"))
    } else {
        Some(hash)
    }
}
