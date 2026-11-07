use anyhow::{Context, Result, bail};
use std::{
    fs,
    path::{Component, Path},
};

pub(crate) fn artifact_path(path: &Path) -> Result<String> {
    path.components()
        .map(|part| match part {
            Component::Normal(value) => value.to_str().context("non-UTF-8 artifact path"),
            _ => bail!("artifact path must be relative"),
        })
        .collect::<Result<Vec<_>>>()
        .map(|parts| parts.join("/"))
}

pub(crate) fn reject_link(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    if metadata.is_symlink() {
        bail!("links are not allowed: {}", path.display());
    }
    #[cfg(windows)]
    {
        use std::os::windows::fs::MetadataExt;
        if metadata.file_attributes() & 0x400 != 0 {
            bail!("reparse points are not allowed: {}", path.display());
        }
    }
    Ok(())
}

pub(crate) fn reject_link_ancestors(path: &Path) -> Result<()> {
    for ancestor in std::path::absolute(path)?.ancestors() {
        reject_link(ancestor)?;
    }
    Ok(())
}

#[cfg(unix)]
pub(crate) fn private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::DirBuilderExt;
    fs::DirBuilder::new().mode(0o700).create(path)?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn private_dir(path: &Path) -> Result<()> {
    use std::{io::Read, process::Stdio};
    crate::verify::valid_path(
        path.file_name()
            .and_then(|name| name.to_str())
            .context("invalid output name")?,
    )?;
    let parent = path.parent().context("output parent")?;
    reject_link_ancestors(parent)?;
    if fs::symlink_metadata(path).is_ok() {
        return Err(std::io::Error::new(
            std::io::ErrorKind::AlreadyExists,
            "output already exists",
        )
        .into());
    }
    let mut command = powershell()?;
    command
        .args([
            "-NoLogo",
            "-NoProfile",
            "-NonInteractive",
            "-Command",
            include_str!("private-directory.ps1"),
        ])
        .env("OPSFORGE_PRIVATE_DIRECTORY", path)
        .stdout(Stdio::piped())
        .stderr(Stdio::inherit());
    let child = crate::runtime::OwnedChild::spawn(&mut command)?;
    let mut output = String::new();
    child.take_stdout()?.read_to_string(&mut output)?;
    if !child.wait()?.success() {
        bail!("could not create a private directory: {}", path.display());
    }
    reject_link(path)?;
    Ok(())
}

#[cfg(windows)]
pub(crate) fn powershell() -> Result<std::process::Command> {
    let root = std::env::var_os("SystemRoot").context("SystemRoot is missing")?;
    Ok(std::process::Command::new(
        Path::new(&root).join("System32/WindowsPowerShell/v1.0/powershell.exe"),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn artifact_names_use_slashes_and_reject_escape() {
        assert_eq!(
            artifact_path(&Path::new("raw").join("file # name")).unwrap(),
            "raw/file # name"
        );
        assert!(artifact_path(Path::new("../escape")).is_err());
    }

    #[cfg(windows)]
    #[test]
    fn private_directory_refuses_overwrite_and_junctions() {
        let parent = std::env::temp_dir().join(format!("opsforge-acl-{}", std::process::id()));
        fs::create_dir(&parent).unwrap();
        let output = parent.join("private # ' ü directory");
        private_dir(&output).unwrap();
        fs::write(output.join("marker"), "keep").unwrap();
        assert!(private_dir(&output).is_err());
        assert_eq!(fs::read_to_string(output.join("marker")).unwrap(), "keep");
        let status = powershell().unwrap().args(["-NoProfile", "-NonInteractive", "-Command",
            "New-Item -ItemType Junction -Path (Join-Path $env:OPSFORGE_TEST_PARENT junction) -Target $env:OPSFORGE_TEST_TARGET | Out-Null"])
            .env("OPSFORGE_TEST_PARENT", &parent).env("OPSFORGE_TEST_TARGET", &output).status().unwrap();
        assert!(status.success());
        let junction = parent.join("junction");
        assert!(reject_link_ancestors(&junction).is_err());
        assert!(private_dir(&junction.join("blocked")).is_err());
        assert!(!output.join("blocked").exists());
        fs::remove_dir(junction).unwrap();
        fs::remove_dir_all(parent).unwrap();
    }
}
