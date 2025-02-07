use serde::{Deserialize, Serialize};
use std::time::Duration;

pub fn default_core_channel() -> usize {
    128
}

#[derive(Debug, Serialize, Clone)]
pub struct Timeout {
    #[serde(default = "default_heartbeat_interval")]
    pub heartbeat_interval: Duration,
    #[serde(default = "default_write")]
    pub write: Duration,
    #[serde(default = "default_tunnel_idle_timeout")]
    pub tunnel_idle: Duration,
    #[serde(default = "default_auth_timeout")]
    pub auth: Duration,
}

impl Default for Timeout {
    fn default() -> Self {
        Self {
            heartbeat_interval: default_heartbeat_interval(),
            tunnel_idle: default_tunnel_idle_timeout(),
            write: default_write_timeout(),
            auth: default_auth_timeout(),
        }
    }
}

fn default_write_timeout() -> Duration {
    std::time::Duration::from_secs(5)
}

fn default_heartbeat_interval() -> Duration {
    std::time::Duration::from_secs(5)
}

fn default_tunnel_idle_timeout() -> Duration {
    std::time::Duration::from_secs(300)
}
fn default_auth_timeout() -> Duration {
    std::time::Duration::from_millis(300)
}

#[derive(Debug, Deserialize, Serialize, Clone, Default)]
#[serde(rename_all = "lowercase")]
pub enum Transport {
    Tcp,
    #[default]
    Quic,
}

impl<'de> Deserialize<'de> for Timeout {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct TimeoutVisitor;

        impl<'de> serde::de::Visitor<'de> for TimeoutVisitor {
            type Value = Timeout;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("struct Timeout")
            }

            fn visit_map<V>(self, mut map: V) -> Result<Timeout, V::Error>
            where
                V: serde::de::MapAccess<'de>,
            {
                let mut heartbeat_interval = default_heartbeat_interval();
                let mut tunnel_idle_timeout = default_tunnel_idle_timeout();
                let mut write_timeout = default_write_timeout();

                while let Some(key) = map.next_key::<String>()? {
                    match key.as_str() {
                        "heartbeat_interval" => {
                            let duration = Duration::from_secs(map.next_value::<u64>()?);
                            heartbeat_interval = if duration < Duration::from_secs(1) {
                                return Err(serde::de::Error::custom(
                                    "heartbeat_interval must be at least 1 second",
                                ));
                            } else {
                                duration
                            };
                        }
                        "tunnel_idle" => {
                            let duration = Duration::from_secs(map.next_value::<u64>()?);
                            tunnel_idle_timeout = if duration < Duration::from_secs(30) {
                                return Err(serde::de::Error::custom(
                                    "tunnel_idle_timeout must be at least 30 seconds",
                                ));
                            } else {
                                duration
                            };
                        }
                        "write" => {
                            let duration = Duration::from_secs(map.next_value::<u64>()?);
                            write_timeout = if duration > Duration::from_secs(10)
                                || duration == Duration::from_secs(0)
                            {
                                return Err(serde::de::Error::custom(
                                    "write timeout should be in range (0, 10] seconds",
                                ));
                            } else {
                                duration
                            };
                        }
                        // Auth deliberately omitted
                        _ => {
                            return Err(serde::de::Error::unknown_field(
                                &key,
                                &["heartbeat_interval", "tunnel_idle", "write"],
                            ));
                        }
                    }
                }

                if tunnel_idle_timeout < heartbeat_interval {
                    return Err(serde::de::Error::custom(format!(
                        "tunnel_idle_timeout ({} secs) must be greater than or equal to heartbeat_interval ({} secs)",
                        tunnel_idle_timeout.as_secs(),
                        heartbeat_interval.as_secs()
                    )));
                }

                Ok(Timeout {
                    heartbeat_interval,
                    write: write_timeout,
                    tunnel_idle: tunnel_idle_timeout,
                    auth: tunnel_idle_timeout,
                })
            }
        }

        deserializer.deserialize_map(TimeoutVisitor)
    }
}
pub const PSK_MAX_LEN: usize = 512;
pub fn de_psk<'de, D>(deserializer: D) -> std::result::Result<String, D::Error>
where
    D: serde::Deserializer<'de>,
{
    let psk: String = String::deserialize(deserializer)?;
    if psk.is_empty() || psk.len() > PSK_MAX_LEN {
        return Err(serde::de::Error::custom(format!(
            "psk must be non-empty and at most {PSK_MAX_LEN} bytes long"
        )));
    }
    Ok(psk)
}
