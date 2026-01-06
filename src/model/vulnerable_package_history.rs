use serde::{Deserialize, Serialize};
use sqlx::FromRow;

use crate::model::Vulnerability;

#[derive(Serialize, Deserialize, FromRow)]
pub struct EnVulnerablePackageHistory {
    pub id: i64,
    pub critical: i16,
    pub high: i16,
    pub medium: i16,
    pub low: i16,
    pub info: i16,
    #[serde(alias = "_unknown", rename = "_unknown")]
    pub unknown: i16,
    #[serde(alias = "_none", rename = "_none")]
    pub none: i16,
    pub created_date: chrono::DateTime<chrono::Utc>,
    pub package_version_id: i64,
}

impl EnVulnerablePackageHistory {
    /**
     * Fills the vulnerabilities (critical, high, medium, low, info, unknown, none) from the CycloneDX ratings severity.
     */
    pub fn update_vulnerable_package_history(
        &mut self,
        vulnerabilities: &Vec<Vulnerability>,
    ) -> () {
        self.critical = 0;
        self.high = 0;
        self.medium = 0;
        self.low = 0;
        self.info = 0;
        self.unknown = 0;
        self.none = 0;

        for vulnerability in vulnerabilities {
            match &vulnerability.ratings {
                Some(ratings) => {
                    for rating in ratings {
                        match &rating.severity {
                            Some(severity) => match severity {
                                crate::model::Severity::Critical => {
                                    self.critical = self.critical + 1;
                                }
                                crate::model::Severity::High => self.high = self.high + 1,
                                crate::model::Severity::Medium => self.medium = self.medium + 1,
                                crate::model::Severity::Low => self.low = self.low + 1,
                                crate::model::Severity::Info => self.info = self.info + 1,
                                crate::model::Severity::None => self.none = self.none + 1,
                                crate::model::Severity::Unknown => self.unknown = self.unknown + 1,
                            },
                            None => {}
                        }
                    }
                }
                None => {}
            }
        }
    }

    /**
     * Has any of the vulnerabilities (critical, high, medium, low, info, unknown, none) changed?
     */
    pub fn has_vulnerability_changed(
        &self,
        vulnerable_package_history: &EnVulnerablePackageHistory,
    ) -> bool {
        return !(self.critical == vulnerable_package_history.critical
            && self.high == vulnerable_package_history.high
            && self.medium == vulnerable_package_history.medium
            && self.low == vulnerable_package_history.low
            && self.info == vulnerable_package_history.info
            && self.unknown == vulnerable_package_history.unknown
            && self.none == vulnerable_package_history.none);
    }
}
