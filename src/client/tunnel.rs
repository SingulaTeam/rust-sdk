//! The node's tunnel settings, decoded.

use prost::Message as _;

use super::ClientError;
use super::proto::node::{SniVariant, VlessCredentials};
use crate::session::Credentials;

/// How to reach a session's node: VLESS over REALITY.
///
/// A node serves each cover two ways on the cover's port, behind the same
/// REALITY: over raw TCP with [`flow`](Self::flow) (Vision), and over xHTTP at
/// the cover's [`xhttp_path`](Cover::xhttp_path), with no flow. Either reaches
/// the same session, under any cover the node serves; which to use is the
/// client's choice, and switching needs no new session.
///
/// The SDK carries no tunnel; hand these to the engine of your choice. They
/// let anyone holding them use the session, so treat them as secret.
#[derive(Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct TunnelSettings {
    /// The VLESS user id.
    pub uuid: String,
    /// The node's address, an IP or a host name.
    pub address: String,
    /// The port of the REALITY inbound for the chosen [`cover`](Self::cover).
    pub port: u16,
    /// The VLESS flow over raw TCP, such as `xtls-rprx-vision`; empty for
    /// none. Over xHTTP no flow is sent.
    pub flow: String,
    /// The node's REALITY public key.
    pub reality_public_key: String,
    /// The TLS fingerprint to imitate, such as `chrome`.
    pub fingerprint: String,
    /// The cover the node chose for this session.
    pub cover: Cover,
    /// Every cover the node serves. The session works under any of them, so
    /// a client whose cover is blocked can switch without a new session —
    /// to one whose [`port`](Cover::port) is known.
    pub covers: Vec<Cover>,
}

/// One cover: a set of server names to present, each with its REALITY short id.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub struct Cover {
    /// The preset's name, such as `default` or `RU`.
    pub preset: String,
    /// `(server name, short id)` pairs; pick one per connection.
    pub names: Vec<(String, String)>,
    /// The path to use over xHTTP, matched exactly by the node; `None` when
    /// the node serves this cover over raw TCP only.
    pub xhttp_path: Option<String>,
    /// The port this cover is reached on: a node may serve each cover on a
    /// port of its own, or all of them on one. `None` when the node does not
    /// name it, as older nodes do not; switch only to covers whose port is
    /// known. The chosen cover's is always known.
    pub port: Option<u16>,
}

impl TunnelSettings {
    /// Decodes a session's credentials.
    ///
    /// # Errors
    ///
    /// Returns [`ClientError::Malformed`] if they do not decode, or lack an
    /// address, a port or a server name.
    pub fn decode(credentials: &Credentials) -> Result<Self, ClientError> {
        let v = VlessCredentials::decode(credentials.as_bytes())
            .map_err(|_| ClientError::Malformed("the tunnel settings do not decode"))?;
        let names = |pool: Vec<SniVariant>| {
            pool.into_iter()
                .map(|n| (n.server_name, n.short_id))
                .collect::<Vec<_>>()
        };

        // Older nodes send one server name in the legacy fields and no pool.
        let mut chosen = names(v.sni_pool);
        if chosen.is_empty() && !v.server_name.is_empty() {
            chosen.push((v.server_name, v.reality_short_id));
        }
        if chosen.is_empty() {
            return Err(ClientError::Malformed("the tunnel settings name no server"));
        }
        let port = match v.endpoint_port {
            0 => u32::try_from(v.port).unwrap_or(0),
            p => p,
        };
        let port = u16::try_from(port)
            .ok()
            .filter(|&p| p != 0)
            .ok_or(ClientError::Malformed("the tunnel port"))?;
        if v.address.is_empty() {
            return Err(ClientError::Malformed(
                "the tunnel settings name no address",
            ));
        }
        Ok(Self {
            uuid: v.uuid,
            address: v.address,
            port,
            flow: v.flow,
            reality_public_key: v.reality_public_key,
            fingerprint: v.fingerprint,
            covers: v
                .covers
                .into_iter()
                .map(|c| {
                    // The chosen cover is reached on the session's port,
                    // whether or not the node names it again.
                    let port = u16::try_from(c.port)
                        .ok()
                        .filter(|&p| p != 0)
                        .or((c.preset_id == v.preset_id).then_some(port));
                    Cover {
                        preset: c.preset_id,
                        names: names(c.sni_pool),
                        xhttp_path: path(c.xhttp_path),
                        port,
                    }
                })
                .collect(),
            cover: Cover {
                preset: v.preset_id,
                names: chosen,
                xhttp_path: path(v.transport_path),
                port: Some(port),
            },
        })
    }
}

/// A path as the wire carries it: empty means none.
fn path(p: String) -> Option<String> {
    (!p.is_empty()).then_some(p)
}

impl std::fmt::Debug for TunnelSettings {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("TunnelSettings")
            .field("port", &self.port)
            .field("cover", &self.cover.preset)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::super::proto::node::CoverOption;
    use super::*;

    fn sealed(v: &VlessCredentials) -> Credentials {
        Credentials::for_tests(v.encode_to_vec())
    }

    #[test]
    fn reads_current_settings() {
        let v = VlessCredentials {
            uuid: "u".into(),
            address: "203.0.113.7".into(),
            port: 443,
            endpoint_port: 8443,
            flow: "xtls-rprx-vision".into(),
            preset_id: "RU".into(),
            sni_pool: vec![SniVariant {
                server_name: "a.example".into(),
                short_id: "ab".into(),
            }],
            transport_path: "/metrika/collect".into(),
            covers: vec![
                CoverOption {
                    preset_id: "default".into(),
                    sni_pool: vec![],
                    xhttp_path: "/api/health/check".into(),
                    port: 443,
                },
                CoverOption {
                    preset_id: "CN".into(),
                    sni_pool: vec![],
                    xhttp_path: String::new(),
                    port: 2053,
                },
            ],
            ..Default::default()
        };
        let s = TunnelSettings::decode(&sealed(&v)).expect("decodes");
        assert_eq!((s.port, s.cover.preset.as_str()), (8443, "RU"));
        assert_eq!(s.cover.names, [("a.example".to_owned(), "ab".to_owned())]);
        assert_eq!(s.cover.xhttp_path.as_deref(), Some("/metrika/collect"));
        assert_eq!(s.covers.len(), 2);
        assert_eq!(s.covers[0].xhttp_path.as_deref(), Some("/api/health/check"));
        assert_eq!(
            s.covers[1].xhttp_path, None,
            "a cover served over raw TCP only"
        );
        assert_eq!(s.cover.port, Some(8443));
        assert_eq!(
            s.covers.iter().map(|c| c.port).collect::<Vec<_>>(),
            [Some(443), Some(2053)],
            "each cover on its own port"
        );
    }

    #[test]
    fn knows_only_the_chosen_covers_port_from_a_node_that_names_none() {
        let cover = |preset: &str| CoverOption {
            preset_id: preset.into(),
            sni_pool: vec![],
            xhttp_path: String::new(),
            port: 0,
        };
        let v = VlessCredentials {
            address: "203.0.113.7".into(),
            endpoint_port: 8443,
            preset_id: "RU".into(),
            server_name: "a.example".into(),
            covers: vec![cover("default"), cover("RU")],
            ..Default::default()
        };
        let s = TunnelSettings::decode(&sealed(&v)).expect("decodes");
        assert_eq!(s.cover.port, Some(8443));
        assert_eq!(
            s.covers.iter().map(|c| c.port).collect::<Vec<_>>(),
            [None, Some(8443)],
            "the chosen cover is reached on the session's port"
        );
    }

    #[test]
    fn reads_an_older_nodes_settings() {
        let v = VlessCredentials {
            address: "203.0.113.7".into(),
            port: 443,
            server_name: "b.example".into(),
            reality_short_id: "cd".into(),
            ..Default::default()
        };
        let s = TunnelSettings::decode(&sealed(&v)).expect("decodes");
        assert_eq!((s.port, s.cover.names[0].0.as_str()), (443, "b.example"));
        assert_eq!(
            s.cover.xhttp_path, None,
            "an older node serves raw TCP only"
        );
    }

    #[test]
    fn refuses_settings_that_lead_nowhere() {
        let v = VlessCredentials {
            address: "203.0.113.7".into(),
            port: 443,
            ..Default::default()
        };
        assert!(TunnelSettings::decode(&sealed(&v)).is_err());
        assert!(TunnelSettings::decode(&Credentials::for_tests(vec![0xff, 0xff])).is_err());
    }
}
