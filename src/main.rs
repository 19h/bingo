use rayon::iter::{IntoParallelIterator, ParallelBridge, ParallelIterator, IntoParallelRefIterator};
use std::fs::OpenOptions;
use std::io::{Read, BufReader, BufRead};
use std::path::Path;
use regex::Regex;

#[derive(Debug, Eq, PartialEq)]
enum FileType {
    Binary,
    Text,
    Unknown,
}

enum FileOp {
    Op(
        std::fs::File,
        std::fs::Metadata,
    ),
    Err(std::io::Error),
}

fn open_file(path: &Path) -> FileOp {
    let mut file =
        match OpenOptions::new()
            .read(true)
            .open(path) {
            Ok(file) => file,
            Err(err) => {
                return FileOp::Err(err);
            }
        };

    let meta =
        match file.metadata() {
            Ok(meta) => meta,
            Err(err) => {
                return FileOp::Err(err);
            }
        };

    FileOp::Op(
        file,
        meta,
    )
}

fn detect_file_type(path: &Path) -> FileType {
    let (mut file, meta) =
        match open_file(path) {
            FileOp::Op(file, meta) =>
                (file, meta),
            _ => {
                return FileType::Unknown;
            }
        };

    let sample_len =
        u64::min(
            meta.len(),
            8000,
        );

    let mut data =
        Vec::with_capacity(
            sample_len as usize,
        );

    data.resize(
        sample_len as usize,
        0,
    );

    file.read(&mut data);

    if data.contains(&0) {
        FileType::Binary
    } else {
        FileType::Text
    }
}

fn main() {
    let regex: Vec<Regex> =
        vec![
            r#"AKIA[0-9A-Z]{16}"#.to_string(),
            r#"(?:\s|=|:|"|^)AKC[a-zA-Z0-9]{10,}"#.to_string(),
            r#"(?:\s|=|:|"|^)AP[\dABCDEF][a-zA-Z0-9]{8,}"#.to_string(),
            r#"AccountKey=[a-zA-Z0-9+/=]{88}"#.to_string(),
            r#"://[^{}\s]+:([^{}\s]+)@"#.to_string(),
            r#"(?:https?://)[w-]+:([0-9a-f]{64})@[w-]+.cloudant.com"#.to_string(),
            r#"(?:https?://)[w-]+:([a-z]{24})@[w-]+.cloudant.com"#.to_string(),
            r#"(?:https?://)(?:[\w\-:%]*@)?[w-]+.cloudant.com"#.to_string(),
            r#"(ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9_]{36}"#.to_string(),
            r#"eyJ[A-Za-z0-9-_=]+\.[A-Za-z0-9-_=]+\.?[A-Za-z0-9-_.+/=]*?"#.to_string(),
            r#"[0-9a-z]{32}-us[0-9]{1,2}"#.to_string(),
            r#"//.+/:_authToken=.+"#.to_string(),
            r#"BEGIN DSA PRIVATE KEY"#.to_string(),
            r#"BEGIN EC PRIVATE KEY"#.to_string(),
            r#"BEGIN OPENSSH PRIVATE KEY"#.to_string(),
            r#"BEGIN PGP PRIVATE KEY BLOCK"#.to_string(),
            r#"BEGIN PRIVATE KEY"#.to_string(),
            r#"BEGIN RSA PRIVATE KEY"#.to_string(),
            r#"BEGIN SSH2 ENCRYPTED PRIVATE KEY"#.to_string(),
            r#"PuTTY-User-Key-File-2"#.to_string(),
            r#"SG\.[a-zA-Z0-9_-]{22}\.[a-zA-Z0-9_-]{43}"#.to_string(),
            r#"xox(?:a|b|p|o|s|r)-(?:\d+-)+[a-z0-9]+"#.to_string(),
            r#"https://hooks.slack.com/services/T[a-zA-Z0-9_]+/B[a-zA-Z0-9_]+/[a-zA-Z0-9_]+"#.to_string(),
            r#"(?:http|https)://api.softlayer.com/soap/(?:v3|v3.1)/([a-z0-9]{64})"#.to_string(),
            r#"sq0csp-[0-9A-Za-z\\\-_]{43}"#.to_string(),
            r#"(?:r|s)k_live_[0-9a-zA-Z]{24}"#.to_string(),
            r#"AC[a-z0-9]{32}"#.to_string(),
            r#"SK[a-z0-9]{32}"#.to_string()
        ]
            .iter()
            .filter_map(
                |item|
                    regex::Regex::new(
                        item
                    ).ok()
            )
            .collect();

    walkdir::WalkDir::new(".")
        .into_iter()
        .par_bridge()
        .for_each(
            |entry| {
                if entry.is_err() {
                    return
                }

                let entry = entry.unwrap();
                let path = entry.path();

                if detect_file_type(path) == FileType::Binary {
                    return;
                }

                let (mut file, meta) =
                    match open_file(path) {
                        FileOp::Op(file, meta) =>
                            (file, meta),
                        _ => {
                            return;
                        }
                    };

                let reader = BufReader::new(file);

                reader
                    .lines()
                    .filter_map(|item| item.ok())
                    .par_bridge()
                    .for_each(|item| {
                        regex
                            .iter()
                            .enumerate()
                            .par_bridge()
                            .for_each(
                                |(line, regex)| {
                                    if let Some(result) = regex.find(&item) {
                                        println!("{}:{}:[{}, {}] - {:?}", path.display(), line, result.start(), result.end(), regex);
                                        println!("{:?}", &result.as_str()[0..usize::min(result.end() - result.start(), 150)]);
                                        println!();
                                    }
                                }
                            );
                    });
            }
        )
}
