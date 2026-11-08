//! Native WSL packet ingress in the single Windows sing-box configuration.
//! This is a strict, reversible projection. The Local Secret Vault owns keys;
//! this code never invents, prints or stores a second credential authority.
use serde_json::{Value, json};
use std::net::Ipv4Addr;

pub const ENDPOINT_TAG: &str = "wsl-kernel";
pub const TRANSPORT_TAG: &str = "wsl-transport-direct";
pub const GUEST_WG_IP: &str = "10.222.28.2/32";
pub const WINDOWS_WG_IP: &str = "10.222.28.1/30";
pub const WG_LISTEN_PORT: u16 = 43912;
pub const WINDOWS_WG_LISTEN_PORT: u16 = 43913;

#[derive(Clone)]
pub struct Layer {
    endpoint: Value,
    outbound: Option<Value>,
    rule: Value,
}
fn expected_rule() -> Value {
    json!({"inbound":[ENDPOINT_TAG], "outbound":"wsl-selector"})
}
fn key_like(s: &str) -> bool {
    s.len() == 44
        && s.ends_with('=')
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'+' || b == b'/' || b == b'=')
}
fn valid_guest_ip(s: &str) -> bool {
    s.parse::<Ipv4Addr>().is_ok_and(|ip| {
        ip.is_private()
            && !ip.is_loopback()
            && !ip.is_link_local()
            && !ip.is_unspecified()
            && !ip.is_broadcast()
    })
}
fn valid_wsl_interface(s: &str) -> bool {
    s.starts_with("vEthernet (WSL")
        && s.ends_with(')')
        && s.len() <= 128
        && s.bytes().all(|b| b.is_ascii_graphic() || b == b' ')
}
fn check_layer(layer: &Layer) -> Result<(), &'static str> {
    let endpoint = &layer.endpoint;
    if endpoint["tag"] != ENDPOINT_TAG
        || endpoint["type"] != "wireguard"
        || endpoint["address"] != json!([WINDOWS_WG_IP])
        || endpoint["private_key"]
            .as_str()
            .is_none_or(|s| !key_like(s))
        || (if endpoint.get("listen_port").is_some() {
            endpoint["listen_port"].as_u64() != Some(u64::from(WINDOWS_WG_LISTEN_PORT))
                || endpoint
                    .get("bind_interface")
                    .is_some_and(|v| v.as_str().is_none_or(|s| !valid_wsl_interface(s)))
                || endpoint.get("inet4_bind_address").is_some_and(|v| v != "0.0.0.0")
                || endpoint.as_object().is_none_or(|o| {
                    o.len()
                        != 6
                            + usize::from(endpoint.get("bind_interface").is_some())
                            + usize::from(endpoint.get("inet4_bind_address").is_some())
                })
                || layer.outbound.is_some()
        } else {
            endpoint["detour"] != TRANSPORT_TAG
                || endpoint.as_object().is_none_or(|o| o.len() != 6)
                || layer.outbound.is_none()
        })
    {
        return Err("WSL_WG_ENDPOINT_UNOWNED");
    }
    let peers = endpoint["peers"].as_array().ok_or("WSL_WG_PEER_INVALID")?;
    if peers.len() != 1 {
        return Err("WSL_WG_PEER_INVALID");
    }
    let p = &peers[0];
    if p.as_object().is_none_or(|o| o.len() != 5)
        || p["public_key"].as_str().is_none_or(|s| !key_like(s))
        || p["address"].as_str().is_none_or(|s| !valid_guest_ip(s))
        || p["port"].as_u64() != Some(u64::from(WG_LISTEN_PORT))
        || p["allowed_ips"] != json!([GUEST_WG_IP])
        || p["persistent_keepalive_interval"] != 2
    {
        return Err("WSL_WG_PEER_INVALID");
    }
    if let Some(outbound) = &layer.outbound
        && (outbound["tag"] != TRANSPORT_TAG
            || outbound["type"] != "direct"
            || outbound.as_object().is_none_or(|o| o.len() != 3)
            || outbound["bind_interface"]
                .as_str()
                .is_none_or(|s| !valid_wsl_interface(s)))
    {
        return Err("WSL_TRANSPORT_INTERFACE_INVALID");
    }
    if layer.rule != expected_rule() {
        return Err("WSL_WG_ROUTE_UNOWNED");
    }
    Ok(())
}

/// Strip only the three known U7 objects. All other native config is unchanged.
/// This also prevents TUN mode transitions from accidentally deleting the layer.
pub fn split(original: &Value) -> Result<(Value, Option<Layer>), &'static str> {
    let Some(endpoints) = original.get("endpoints") else {
        return Ok((original.clone(), None));
    };
    let endpoints = endpoints.as_array().ok_or("WSL_ENDPOINTS_INVALID")?;
    if endpoints.len() != 1 {
        return Err("WSL_ENDPOINTS_UNOWNED");
    }
    // Version 1 used a separate detour outbound; version 2 uses the
    // endpoint's native bind_interface and listen_port. Preserve both
    // shapes for checked migration without accepting foreign layers.
    let outbound = if endpoints[0].get("listen_port").is_some() {
        None
    } else {
        Some(
            original["outbounds"]
                .as_array()
                .and_then(|v| v.last())
                .ok_or("WSL_TRANSPORT_MISSING")?
                .clone(),
        )
    };
    let rule = original
        .pointer("/route/rules")
        .and_then(Value::as_array)
        .and_then(|v| v.last())
        .ok_or("WSL_WG_ROUTE_MISSING")?
        .clone();
    let layer = Layer {
        endpoint: endpoints[0].clone(),
        outbound,
        rule,
    };
    check_layer(&layer)?;
    let mut clean = original.clone();
    clean
        .as_object_mut()
        .ok_or("CONFIG_JSON_INVALID")?
        .remove("endpoints");
    if layer.outbound.is_some() {
        clean["outbounds"]
            .as_array_mut()
            .ok_or("CONFIG_OUTBOUNDS_MISSING")?
            .pop();
    }
    clean
        .pointer_mut("/route/rules")
        .and_then(Value::as_array_mut)
        .ok_or("CONFIG_ROUTE_RULES_MISSING")?
        .pop();
    Ok((clean, Some(layer)))
}

pub fn attach(base: &Value, layer: Option<&Layer>) -> Result<Value, &'static str> {
    let Some(layer) = layer else {
        return Ok(base.clone());
    };
    check_layer(layer)?;
    if base.get("endpoints").is_some() {
        return Err("WSL_WG_ALREADY_CONFIGURED");
    }
    let mut next = base.clone();
    next["endpoints"] = json!([layer.endpoint]);
    if let Some(outbound) = &layer.outbound {
        next["outbounds"]
            .as_array_mut()
            .ok_or("CONFIG_OUTBOUNDS_MISSING")?
            .push(outbound.clone());
    }
    next.pointer_mut("/route/rules")
        .and_then(Value::as_array_mut)
        .ok_or("CONFIG_ROUTE_RULES_MISSING")?
        .push(layer.rule.clone());
    Ok(next)
}

pub struct Options<'a> {
    pub guest_ip: Ipv4Addr,
    pub wsl_interface: &'a str,
    pub windows_private_key: &'a str,
    pub guest_public_key: &'a str,
}

pub fn render(original: &Value, opts: &Options<'_>) -> Result<Value, &'static str> {
    crate::config::validate(original)?;
    let (base, existing) = split(original)?;
    if existing.is_some() {
        return Err("WSL_WG_ALREADY_CONFIGURED");
    }
    if !valid_guest_ip(&opts.guest_ip.to_string())
        || !valid_wsl_interface(opts.wsl_interface)
        || !key_like(opts.windows_private_key)
        || !key_like(opts.guest_public_key)
    {
        return Err("WSL_WG_OPTIONS_INVALID");
    }
    let layer = Layer {
        endpoint: json!({
            "type":"wireguard", "tag":ENDPOINT_TAG,
            "address":[WINDOWS_WG_IP],
            "private_key":opts.windows_private_key,
            "listen_port":WINDOWS_WG_LISTEN_PORT,
            // Preserve Windows route.auto_detect_interface for Windows TUN,
            // but prevent its UDP listener-control from binding this optional
            // WireGuard socket to the wrong interface after cold boot.
            "inet4_bind_address":"0.0.0.0",
            // The exact owned Windows Firewall rule limits remote UDP ingress
            // to the WSL adapter and current native NAT guest address.
            "peers":[{
                "address":opts.guest_ip.to_string(),
                "port": WG_LISTEN_PORT,
                "public_key":opts.guest_public_key,
                "allowed_ips":[GUEST_WG_IP],
                "persistent_keepalive_interval":2
            }]
        }),
        outbound: None,
        rule: expected_rule(),
    };
    let next = attach(&base, Some(&layer))?;
    crate::config::validate(&next)?;
    Ok(next)
}

/// Called only while the native Windows task is stopped. The optional
/// WireGuard listener must not depend on a WSL adapter that starts later.
/// The existing firewall still restricts UDP ingress to the owned WSL NIC.
pub fn prepare_at_windows_start(current: &Value) -> Result<Value, &'static str> {
    let (_, layer) = split(current)?;
    let Some(layer) = layer else {
        return Ok(current.clone());
    };
    if layer.endpoint.get("listen_port").is_none() {
        return Ok(current.clone());
    }
    if layer.endpoint.get("bind_interface").is_none()
        && layer.endpoint.get("inet4_bind_address") == Some(&json!("0.0.0.0"))
    {
        return Ok(current.clone());
    }
    let mut next = current.clone();
    let endpoint = next["endpoints"][0]
        .as_object_mut()
        .ok_or("WSL_WG_ENDPOINT_UNOWNED")?;
    endpoint.remove("bind_interface");
    endpoint.insert("inet4_bind_address".to_owned(), json!("0.0.0.0"));
    split(&next)?;
    Ok(next)
}

pub fn remove(original: &Value) -> Result<Value, &'static str> {
    crate::config::validate(original)?;
    let (base, _) = split(original)?;
    crate::config::validate(&base)?;
    Ok(base)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn fixed_windows_port_and_legacy_layer_round_trip_without_second_owner() {
        let key = format!("{}=", "A".repeat(43));
        let iface = "vEthernet (WSL (Hyper-V firewall))";
        let peer = json!({
            "address":"172.26.23.199", "port":43912,
            "public_key":key, "allowed_ips":[GUEST_WG_IP],
            "persistent_keepalive_interval":2
        });
        let modern = Layer {
            endpoint: json!({
                "type":"wireguard", "tag":ENDPOINT_TAG,
                "address":[WINDOWS_WG_IP], "private_key":key,
                "listen_port":WINDOWS_WG_LISTEN_PORT, "bind_interface":iface,
                "peers":[peer]
            }),
            outbound: None,
            rule: expected_rule(),
        };
        assert!(check_layer(&modern).is_ok());
        // The old interface-bound listener is accepted for one-time migration.
        // The new listener has no WSL boot-order dependency.
        let mut independent = modern.clone();
        independent
            .endpoint
            .as_object_mut()
            .unwrap()
            .remove("bind_interface");
        assert!(check_layer(&independent).is_ok());
        assert_eq!(independent.endpoint.as_object().unwrap().len(), 6);
        let base = json!({"outbounds":[{"type":"direct","tag":"main"}],
            "route":{"rules":[]}});
        let candidate = attach(&base, Some(&modern)).unwrap();
        let unbound = prepare_at_windows_start(&candidate).unwrap();
        assert!(unbound["endpoints"][0].get("bind_interface").is_none());
        assert_eq!(unbound["endpoints"][0]["inet4_bind_address"], "0.0.0.0");
        assert_eq!(
            unbound["endpoints"][0]["listen_port"],
            WINDOWS_WG_LISTEN_PORT
        );
        assert_eq!(
            unbound["endpoints"][0]["peers"],
            candidate["endpoints"][0]["peers"]
        );
        assert_eq!(prepare_at_windows_start(&unbound).unwrap(), unbound);
        assert_eq!(prepare_at_windows_start(&base).unwrap(), base);
        let prepared_from_unbound = prepare_at_windows_start(
            &attach(&base, Some(&independent)).unwrap()
        ).unwrap();
        assert_eq!(prepared_from_unbound, unbound);
        let mut bad_bind = unbound.clone();
        bad_bind["endpoints"][0]["inet4_bind_address"] = json!("127.0.0.1");
        assert_eq!(split(&bad_bind).err(), Some("WSL_WG_ENDPOINT_UNOWNED"));
        let (restored, layer) = split(&candidate).unwrap();
        assert_eq!(restored, base);
        assert!(layer.unwrap().outbound.is_none());
        let mut unsafe_endpoint = modern.clone();
        unsafe_endpoint.endpoint["bind_interface"] = json!("Ethernet");
        assert_eq!(
            check_layer(&unsafe_endpoint),
            Err("WSL_WG_ENDPOINT_UNOWNED")
        );
        unsafe_endpoint = modern.clone();
        unsafe_endpoint.endpoint["listen_port"] = json!(443);
        assert_eq!(
            check_layer(&unsafe_endpoint),
            Err("WSL_WG_ENDPOINT_UNOWNED")
        );

        let legacy = Layer {
            endpoint: json!({
                "type":"wireguard", "tag":ENDPOINT_TAG,
                "address":[WINDOWS_WG_IP], "private_key":key,
                "detour":TRANSPORT_TAG, "peers":[peer]
            }),
            outbound: Some(json!({"type":"direct","tag":TRANSPORT_TAG,
                "bind_interface":iface})),
            rule: expected_rule(),
        };
        assert!(check_layer(&legacy).is_ok());
        let legacy_config = attach(&base, Some(&legacy)).unwrap();
        let (old_base, old_layer) = split(&legacy_config).unwrap();
        assert_eq!(old_base, base);
        assert!(old_layer.unwrap().outbound.is_some());
    }

    #[test]
    fn no_secret_in_debug_or_errors() {
        let bad = json!({"endpoints":[{"tag":"fake","private_key":"SECRET"}],
            "outbounds":[{"tag":"fake"}], "route":{"rules":[{"inbound":["fake"]}]}});
        let result = split(&bad);
        assert!(result.is_err());
        assert!(!result.err().unwrap().contains("SECRET"));
        assert!(!valid_guest_ip("127.0.0.1"));
        assert!(!valid_wsl_interface("Ethernet"));
        assert!(!key_like("not-a-private-key"));
    }
}
