//! Streaming wordlist enumeration and FUZZ substitution.
//!
//! Nothing here is HTTP-specific: the same iterator drives DNS brute forcing
//! in stage 2. Wordlists are read line by line; a whole list is never loaded
//! into memory.

use std::fmt;
use std::fs::File;
use std::io::{BufRead, BufReader};
use std::path::PathBuf;
use std::str::FromStr;

pub const FUZZ: &str = "FUZZ";
pub const FUZZ2: &str = "FUZZ2";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum Mode {
    Pitchfork,
    #[default]
    Clusterbomb,
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Mode::Pitchfork => f.write_str("pitchfork"),
            Mode::Clusterbomb => f.write_str("clusterbomb"),
        }
    }
}

impl FromStr for Mode {
    type Err = String;

    fn from_str(value: &str) -> Result<Self, Self::Err> {
        match value.to_ascii_lowercase().as_str() {
            "pitchfork" => Ok(Mode::Pitchfork),
            "clusterbomb" => Ok(Mode::Clusterbomb),
            other => Err(format!(
                "unknown mode `{other}` (expected pitchfork or clusterbomb)"
            )),
        }
    }
}

/// One position set. `first` fills `FUZZ`, `second` fills `FUZZ2`.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WordSet {
    pub first: String,
    pub second: Option<String>,
}

impl WordSet {
    pub fn single(first: impl Into<String>) -> Self {
        Self {
            first: first.into(),
            second: None,
        }
    }

    pub fn pair(first: impl Into<String>, second: impl Into<String>) -> Self {
        Self {
            first: first.into(),
            second: Some(second.into()),
        }
    }

    pub fn values(&self) -> Vec<&str> {
        match &self.second {
            Some(second) => vec![&self.first, second],
            None => vec![&self.first],
        }
    }
}

/// Replace every `FUZZ2` then every `FUZZ` occurrence in a template field.
/// `FUZZ2` must be replaced first because `FUZZ` is its prefix.
pub fn substitute(template: &str, words: &WordSet) -> String {
    let mut rendered = template.to_string();
    if let Some(second) = &words.second {
        rendered = rendered.replace(FUZZ2, second);
    }
    rendered.replace(FUZZ, &words.first)
}

#[derive(Debug, Clone)]
pub struct WordlistSpec {
    pub first: PathBuf,
    pub second: Option<PathBuf>,
    pub mode: Mode,
}

impl WordlistSpec {
    pub fn new(first: PathBuf, second: Option<PathBuf>, mode: Mode) -> Self {
        Self {
            first,
            second,
            mode,
        }
    }

    pub fn iter(&self) -> std::io::Result<WordlistIter> {
        let first = BufReader::new(File::open(&self.first)?);
        let second = if self.mode == Mode::Pitchfork {
            match &self.second {
                Some(path) => Some(BufReader::new(File::open(path)?)),
                None => None,
            }
        } else {
            None
        };
        Ok(WordlistIter {
            mode: self.mode,
            first,
            second_path: self.second.clone(),
            second,
            cluster_inner: None,
            cluster_current: None,
            done: false,
        })
    }
}

pub struct WordlistIter {
    mode: Mode,
    first: BufReader<File>,
    second_path: Option<PathBuf>,
    second: Option<BufReader<File>>,
    cluster_inner: Option<BufReader<File>>,
    cluster_current: Option<String>,
    done: bool,
}

impl Iterator for WordlistIter {
    type Item = std::io::Result<WordSet>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.done {
            return None;
        }

        match self.mode {
            Mode::Pitchfork => self.next_pitchfork(),
            Mode::Clusterbomb => self.next_clusterbomb(),
        }
    }
}

impl WordlistIter {
    fn next_pitchfork(&mut self) -> Option<std::io::Result<WordSet>> {
        let first = match read_nonempty(&mut self.first) {
            Ok(Some(line)) => line,
            Ok(None) => return None,
            Err(err) => {
                self.done = true;
                return Some(Err(err));
            }
        };

        let Some(second_reader) = self.second.as_mut() else {
            return Some(Ok(WordSet::single(first)));
        };

        match read_nonempty(second_reader) {
            Ok(Some(second)) => Some(Ok(WordSet::pair(first, second))),
            Ok(None) => None,
            Err(err) => {
                self.done = true;
                Some(Err(err))
            }
        }
    }

    fn next_clusterbomb(&mut self) -> Option<std::io::Result<WordSet>> {
        if self.second_path.is_none() {
            return match read_nonempty(&mut self.first) {
                Ok(Some(line)) => Some(Ok(WordSet::single(line))),
                Ok(None) => None,
                Err(err) => {
                    self.done = true;
                    Some(Err(err))
                }
            };
        }

        loop {
            if let Some(inner) = self.cluster_inner.as_mut() {
                match read_nonempty(inner) {
                    Ok(Some(second)) => {
                        let first = self
                            .cluster_current
                            .clone()
                            .expect("cluster current is set with inner reader");
                        return Some(Ok(WordSet::pair(first, second)));
                    }
                    Ok(None) => {
                        self.cluster_inner = None;
                        self.cluster_current = None;
                        continue;
                    }
                    Err(err) => {
                        self.done = true;
                        return Some(Err(err));
                    }
                }
            }

            let first = match read_nonempty(&mut self.first) {
                Ok(Some(line)) => line,
                Ok(None) => return None,
                Err(err) => {
                    self.done = true;
                    return Some(Err(err));
                }
            };

            let path = self
                .second_path
                .as_ref()
                .expect("second path checked above");
            match File::open(path) {
                Ok(file) => {
                    self.cluster_inner = Some(BufReader::new(file));
                    self.cluster_current = Some(first);
                }
                Err(err) => {
                    self.done = true;
                    return Some(Err(err));
                }
            }
        }
    }
}

fn read_nonempty(reader: &mut BufReader<File>) -> std::io::Result<Option<String>> {
    loop {
        let mut line = String::new();
        let read = reader.read_line(&mut line)?;
        if read == 0 {
            return Ok(None);
        }
        let trimmed = line.trim_end_matches(|ch| ch == '\n' || ch == '\r');
        if trimmed.is_empty() {
            continue;
        }
        return Ok(Some(trimmed.to_string()));
    }
}

/// Wrap a word iterator so every entry is emitted once unmodified and once per
/// extension appended to `FUZZ` (the `FUZZ2` position is paired unchanged).
pub fn expand_extensions<I>(inner: I, extensions: Vec<String>) -> ExtensionIter<I>
where
    I: Iterator<Item = std::io::Result<WordSet>>,
{
    ExtensionIter {
        inner,
        extensions,
        pending: Vec::new().into_iter(),
    }
}

pub struct ExtensionIter<I> {
    inner: I,
    extensions: Vec<String>,
    pending: std::vec::IntoIter<std::io::Result<WordSet>>,
}

impl<I> Iterator for ExtensionIter<I>
where
    I: Iterator<Item = std::io::Result<WordSet>>,
{
    type Item = std::io::Result<WordSet>;

    fn next(&mut self) -> Option<Self::Item> {
        loop {
            if let Some(item) = self.pending.next() {
                return Some(item);
            }

            let item = self.inner.next()?;
            let words = match item {
                Ok(words) => words,
                Err(err) => return Some(Err(err)),
            };

            let mut variants = Vec::with_capacity(self.extensions.len() + 1);
            variants.push(Ok(words.clone()));
            for extension in &self.extensions {
                let mut variant = words.clone();
                variant.first.push_str(extension);
                variants.push(Ok(variant));
            }
            self.pending = variants.into_iter();
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn substitution_replaces_every_position() {
        let words = WordSet::pair("admin", "example");
        assert_eq!(
            substitute("https://FUZZ.FUZZ2/FUZZ?x=FUZZ2", &words),
            "https://admin.example/admin?x=example"
        );
    }
}
