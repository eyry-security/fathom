//! Response calibration (ffuf `-ac` equivalent).
//!
//! Random probe entries are sent before the main run. Successful probes build
//! a set of baseline signatures (status, size, word count, line count). During
//! the run, any response whose signature matches a baseline is auto-filtered.

use crate::types::{Response, Signature};

#[derive(Debug, Clone, Default)]
pub struct Calibration {
    pub enabled: bool,
    pub signatures: Vec<Signature>,
}

impl Calibration {
    pub fn new(enabled: bool, signatures: Vec<Signature>) -> Self {
        let mut calibration = Self {
            enabled,
            signatures: Vec::new(),
        };
        for signature in signatures {
            calibration.push_signature(signature);
        }
        calibration
    }

    pub fn add_response(&mut self, response: &Response) {
        self.push_signature(Signature::from(response));
    }

    pub fn matches(&self, response: &Response) -> bool {
        self.enabled && self.signatures.contains(&Signature::from(response))
    }

    fn push_signature(&mut self, signature: Signature) {
        if !self.signatures.contains(&signature) {
            self.signatures.push(signature);
        }
    }
}
