pub mod config;
pub mod diagnostic;
pub mod egress;
pub mod lifecycle;
pub mod model;
pub mod proxies;
pub mod selector;
pub mod tun;
pub mod wsl;
pub mod wsl_tun;

pub const ROOT: &str = r"C:\internet";
pub const TASK: &str = "INTERNET-SingBox";
