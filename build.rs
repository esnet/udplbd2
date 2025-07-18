// SPDX-License-Identifier: BSD-3-Clause-LBNL
use prost_wkt_build::*;
use std::{env, error::Error, fmt, path::PathBuf, process::Command};

// Custom error type
#[derive(Debug)]
enum CommandError {
    Io(std::io::Error),
    Process { program: String, code: Option<i32> },
    Utf8(String),
}

impl fmt::Display for CommandError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            CommandError::Io(err) => write!(f, "IO error: {err}"),
            CommandError::Process { program, code } => match code {
                Some(code) => write!(f, "{program}: terminated with {code}"),
                None => write!(f, "{program}: killed by signal"),
            },
            CommandError::Utf8(msg) => write!(f, "git: invalid output: {msg}"),
        }
    }
}

impl Error for CommandError {
    fn source(&self) -> Option<&(dyn Error + 'static)> {
        match self {
            CommandError::Io(err) => Some(err),
            _ => None,
        }
    }
}

fn command(
    prog: &str,
    args: &[&str],
    cwd: Option<std::path::PathBuf>,
) -> Result<Vec<u8>, CommandError> {
    println!("cargo:rerun-if-env-changed=PATH");
    let mut cmd = Command::new(prog);
    cmd.args(args);
    cmd.stderr(std::process::Stdio::inherit());
    if let Some(cwd) = cwd {
        cmd.current_dir(cwd);
    }
    let out = cmd.output().map_err(CommandError::Io)?;
    if out.status.success() {
        let mut stdout = out.stdout;
        if let Some(b'\n') = stdout.last() {
            stdout.pop();
            if let Some(b'\r') = stdout.last() {
                stdout.pop();
            }
        }
        Ok(stdout)
    } else {
        Err(CommandError::Process {
            program: prog.to_string(),
            code: out.status.code(),
        })
    }
}

// based on implementation from near/nearcore, used under MIT license
fn get_git_version() -> Result<String, CommandError> {
    let pkg_dir = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    let git_dir = command("git", &["rev-parse", "--git-dir"], Some(pkg_dir));
    let git_dir = match git_dir {
        Ok(git_dir) => std::path::PathBuf::from(String::from_utf8(git_dir).unwrap()),
        Err(msg) => {
            println!("cargo:warning=unable to determine git version (not in git repository?)");
            println!("cargo:warning={msg}");
            return Ok("unknown".to_string());
        }
    };

    for subpath in ["HEAD", "logs/HEAD", "index"] {
        let path = git_dir
            .join(subpath)
            .canonicalize()
            .map_err(CommandError::Io)?;
        println!("cargo:rerun-if-changed={}", path.display());
    }

    let args = &[
        "describe",
        "--always",
        "--dirty=-modified",
        "--tags",
        "--match=[0-9]*",
    ];
    let out = command("git", args, None)?;
    match String::from_utf8_lossy(&out) {
        std::borrow::Cow::Borrowed(version) => Ok(version.trim().to_string()),
        std::borrow::Cow::Owned(version) => Err(CommandError::Utf8(version)),
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Tell cargo to regenerate if any proto files change
    println!("cargo:rerun-if-changed=proto/");

    let out = PathBuf::from(env::var("OUT_DIR").unwrap());
    let descriptor_file = out.join("descriptors.bin");

    // Compile SmartNIC protos
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .out_dir("src/proto/smartnic")
        .compile_protos(
            &[
                "proto/smartnic/sn_p4_v2.proto",
                "proto/smartnic/sn_cfg_v2.proto",
            ],
            &["proto/smartnic/"],
        )?;

    // For future loadbalancer service protos
    tonic_build::configure()
        .build_client(true)
        .build_server(true)
        .out_dir("src/proto/loadbalancer")
        .type_attribute(".", "#[derive(serde::Serialize,serde::Deserialize)]")
        .extern_path(".google.protobuf.Any", "::prost_wkt_types::Any")
        .extern_path(".google.protobuf.Timestamp", "::prost_wkt_types::Timestamp")
        .extern_path(".google.protobuf.Value", "::prost_wkt_types::Value")
        .extern_path(".google.protobuf.Struct", "::prost_wkt_types::Struct")
        .file_descriptor_set_path(&descriptor_file)
        .compile_protos(
            &["proto/loadbalancer/loadbalancer.proto"],
            &["proto/loadbalancer/"],
        )?;

    let descriptor_bytes = std::fs::read(descriptor_file).unwrap();
    let descriptor = FileDescriptorSet::decode(&descriptor_bytes[..]).unwrap();

    prost_wkt_build::add_serde(out, descriptor);

    println!("cargo:rustc-env=UDPLBD_BUILD={}", get_git_version()?);

    Ok(())
}
