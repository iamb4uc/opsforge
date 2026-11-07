use anyhow::{Context, Result, bail};
use serde::Serialize;
use std::{
    fs,
    path::{Path, PathBuf},
};

#[derive(Clone, Copy, Debug, Default, clap::ValueEnum, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum ReviewMode {
    #[default]
    Bundle,
    Linked,
}

pub fn rebuild(
    source: &Path,
    output: &Path,
    mode: ReviewMode,
    allow_unverified: bool,
) -> Result<PathBuf> {
    let verification = crate::verify::verify(source)?;
    if !verification.source_issues.is_empty() {
        bail!(
            "source integrity failures: {:?}",
            verification.source_issues
        );
    }
    if !allow_unverified && !verification.unverified.is_empty() {
        bail!("missing integrity metadata; use --allow-unverified to create a labelled review");
    }
    let source = fs::canonicalize(source)?;
    let before = fingerprints(&source)?;
    if source.join("review.json").exists() {
        bail!("rebuild from the original acquisition case, not an existing review");
    }
    let parent = output
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or(Path::new("."));
    crate::platform::reject_link_ancestors(parent)?;
    let parent = fs::canonicalize(parent).context("output parent must already exist")?;
    let name = output
        .file_name()
        .context("output must name a new directory")?;
    let output = parent.join(name);
    if output.starts_with(&source) || source.starts_with(&output) {
        bail!("output overlaps the source case");
    }
    let evidence_base = match mode {
        ReviewMode::Bundle => "../".to_owned(),
        ReviewMode::Linked => relative_url(&output.join("dashboard"), &source)?,
    };
    crate::platform::private_dir(&output).context("output must not exist")?;
    let mut review = serde_json::json!({"status":"in_progress", "mode":mode,"source":source,
        "tool_version":env!("CARGO_PKG_VERSION"),"rebuilt_at":jiff::Timestamp::now().to_string(),
        "review_platform":std::env::consts::OS,
        "verification":verification,"evidence_base":evidence_base});
    fs::write(
        output.join("review.json"),
        serde_json::to_vec_pretty(&review)?,
    )?;
    let result = (|| -> Result<()> {
        for entry in walkdir::WalkDir::new(&source).follow_links(false) {
            let entry = entry?;
            crate::platform::reject_link(entry.path())?;
            if entry.file_type().is_dir() {
                continue;
            }
            if !entry.file_type().is_file() {
                bail!("source changed: non-regular file");
            }
            let relative = entry.path().strip_prefix(&source)?;
            let name = crate::platform::artifact_path(relative)?;
            if crate::verify::generated(&name)
                || matches!(mode, ReviewMode::Linked) && name.starts_with("raw/")
            {
                continue;
            }
            let target = if name == "checksums.sha256" {
                output.join("source-checksums.sha256")
            } else {
                output.join(relative)
            };
            if target.exists() {
                bail!("reserved or duplicate review artifact: {name}");
            }
            fs::create_dir_all(target.parent().context("target parent")?)?;
            // New files inherit the private output ACL instead of copying source ACLs.
            let mut input = fs::File::open(entry.path())?;
            let mut copy = fs::OpenOptions::new()
                .write(true)
                .create_new(true)
                .open(&target)?;
            std::io::copy(&mut input, &mut copy)?;
            drop(copy);
            if crate::verify::digest(entry.path())? != crate::verify::digest(&target)? {
                bail!("source changed while copying: {name}");
            }
        }
        let after = crate::verify::verify(&source)?;
        if serde_json::to_value(&after)? != review["verification"]
            || fingerprints(&source)? != before
        {
            bail!("source changed during rebuild");
        }
        fs::create_dir_all(output.join("dashboard"))?;
        review["status"] = "finished".into();
        crate::report::generate_review(&output, &evidence_base, Some(&review))?;
        fs::write(
            output.join("review.json"),
            serde_json::to_vec_pretty(&review)?,
        )?;
        crate::report::write_checksums(&output)?;
        Ok(())
    })();
    match &result {
        Ok(()) => review["status"] = "finished".into(),
        Err(error) => {
            review["status"] = "failed".into();
            review["error"] = format!("{error:#}").into();
        }
    }
    if result.is_err() {
        fs::write(
            output.join("review.json"),
            serde_json::to_vec_pretty(&review)?,
        )?;
    }
    result.with_context(|| format!("incomplete review retained at {}", output.display()))?;
    Ok(output)
}

fn fingerprints(root: &Path) -> Result<std::collections::BTreeMap<PathBuf, (String, u64)>> {
    let mut files = std::collections::BTreeMap::new();
    for entry in walkdir::WalkDir::new(root).follow_links(false) {
        let entry = entry?;
        crate::platform::reject_link(entry.path())?;
        if entry.file_type().is_dir() {
            continue;
        }
        if !entry.file_type().is_file() {
            bail!("source contains a link or special file");
        }
        files.insert(
            entry.path().strip_prefix(root)?.to_owned(),
            crate::verify::digest(entry.path())?,
        );
    }
    Ok(files)
}

fn relative_url(from: &Path, to: &Path) -> Result<String> {
    let a = from.components().collect::<Vec<_>>();
    let b = to.components().collect::<Vec<_>>();
    let common = a.iter().zip(&b).take_while(|(x, y)| x == y).count();
    if common == 0 {
        bail!("linked output needs a common filesystem root; use bundle mode");
    }
    let mut result = "../".repeat(a.len() - common);
    for component in &b[common..] {
        for byte in component
            .as_os_str()
            .to_str()
            .context("non-UTF-8 source path")?
            .bytes()
        {
            if byte.is_ascii_alphanumeric() || b"-_.~".contains(&byte) {
                result.push(char::from(byte));
            } else {
                result.push_str(&format!("%{byte:02X}"));
            }
        }
        result.push('/');
    }
    Ok(result)
}

#[cfg(all(test, windows))]
mod tests {
    use super::*;
    #[test]
    fn linked_paths_refuse_other_volumes_and_encode_names() {
        assert!(relative_url(Path::new(r"C:\review\dashboard"), Path::new(r"D:\source")).is_err());
        assert_eq!(
            relative_url(
                Path::new(r"C:\review\dashboard"),
                Path::new(r"C:\source # case")
            )
            .unwrap(),
            "../../source%20%23%20case/"
        );
    }
}
