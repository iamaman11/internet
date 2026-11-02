use serde::{Deserialize, Serialize};
use std::{fmt, str::FromStr};

pub const ROUTES: [&str; 6] = [
    "direct-auto", "direct-hysteria2", "direct-vless",
    "warp-auto", "warp-hysteria2", "warp-vless",
];

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum Route {
    DirectAuto,
    DirectHysteria2,
    DirectVless,
    WarpAuto,
    WarpHysteria2,
    WarpVless,
}

impl Route {
    pub fn tag(self) -> &'static str {
        match self {
            Self::DirectAuto => "direct-auto",
            Self::DirectHysteria2 => "direct-hysteria2",
            Self::DirectVless => "direct-vless",
            Self::WarpAuto => "warp-auto",
            Self::WarpHysteria2 => "warp-hysteria2",
            Self::WarpVless => "warp-vless",
        }
    }
}
impl fmt::Display for Route {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(self.tag()) }
}
impl FromStr for Route {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "direct-auto" => Ok(Self::DirectAuto),
            "direct-hysteria2" => Ok(Self::DirectHysteria2),
            "direct-vless" => Ok(Self::DirectVless),
            "warp-auto" => Ok(Self::WarpAuto),
            "warp-hysteria2" => Ok(Self::WarpHysteria2),
            "warp-vless" => Ok(Self::WarpVless),
            _ => Err(format!("ROUTE_UNSUPPORTED: {s}")),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target { Desktop, Wsl }
impl Target {
    pub fn selector(self) -> &'static str {
        match self { Self::Desktop => "desktop-selector", Self::Wsl => "wsl-selector" }
    }
    pub fn listener(self) -> &'static str {
        match self { Self::Desktop => "desktop-in", Self::Wsl => "wsl-in" }
    }
}

#[derive(Debug, Serialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum Health { Healthy, Degraded, Failed, Unknown, Stale, Unsupported }

#[derive(Debug, Serialize)]
pub struct Diagnostic {
    pub resource_id: String,
    pub kind: &'static str,
    pub parent: Option<&'static str>,
    pub owner: &'static str,
    pub dependencies: Vec<&'static str>,
    pub health: Health,
    pub reason_code: &'static str,
    pub source: &'static str,
    pub observed_at: Option<String>,
    pub expected: Option<String>,
    pub actual: Option<String>,
    pub next_action: &'static str,
    pub scope: &'static str,
}

impl Diagnostic {
    pub fn unknown(id: &str, kind: &'static str, owner: &'static str, next: &'static str) -> Self {
        Self {
            resource_id: id.into(), kind, parent: None, owner, dependencies: vec![],
            health: Health::Unknown, reason_code: "NOT_CHECKED", source: "none",
            observed_at: None, expected: None, actual: None, next_action: next, scope: "not_checked",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test] fn six_and_only_six() {
        assert_eq!(ROUTES.len(), 6);
        for tag in ROUTES {
            assert_eq!(tag.parse::<Route>().unwrap().to_string(), tag);
        }
        assert!("warp-direct".parse::<Route>().is_err());
        assert!("".parse::<Route>().is_err());
    }
    #[test] fn targets_are_independent() {
        assert_ne!(Target::Desktop.selector(), Target::Wsl.selector());
        assert_ne!(Target::Desktop.listener(), Target::Wsl.listener());
    }
    #[test] fn unknown_never_has_fabricated_observation() {
        let d = Diagnostic::unknown("vultr/vm", "vm", "vultr", "internet status --deep");
        assert_eq!(d.health, Health::Unknown);
        assert!(d.observed_at.is_none());
        assert_eq!(d.source, "none");
    }
}
