//! macOS fallback for the full listening-port set.
//!
//! `netstat2` on macOS walks processes and asks libproc for their file
//! descriptors. Without root, `PROC_PIDLISTFDS` fails for processes owned by
//! other users, and the crate silently skips them, so their listening ports
//! disappear from the inventory completely.
//!
//! `/usr/sbin/netstat`, which reads the kernel PCB lists, sees every listening
//! socket regardless of ownership. We use it only to recover the port/address
//! set; ownership for those entries stays unknown (`-` in the tables), which is
//! the documented user-level fallback. The parser is exercised by unit tests
//! with real macOS output.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::process::Command;

const NETSTAT: &str = "/usr/sbin/netstat";

/// Return every TCP `LISTEN` socket reported by `netstat`, as `(port, bind)`.
///
/// Returns an empty vector when the command cannot be run or fails; the
/// caller then keeps the (possibly incomplete) `netstat2` result.
pub fn all_tcp_listeners() -> Vec<(u16, IpAddr)> {
    let output = match Command::new(NETSTAT).args(["-an", "-p", "tcp"]).output() {
        Ok(output) if output.status.success() => output,
        _ => return Vec::new(),
    };
    parse_netstat(&String::from_utf8_lossy(&output.stdout))
}

/// Parse macOS `netstat -an -p tcp` output.
///
/// Lines look like:
///
/// ```text
/// tcp4       0      0  127.0.0.1.18090        *.*                    LISTEN
/// tcp6       0      0  ::1.18092              *.*                    LISTEN
/// tcp46      0      0  *.47811                *.*                    LISTEN
/// tcp6       0      0  fe80::1%lo0.8080       *.*                    LISTEN
/// ```
fn parse_netstat(text: &str) -> Vec<(u16, IpAddr)> {
    let mut result = Vec::new();
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        if fields.len() < 6 || fields[0] != "tcp4" && fields[0] != "tcp6" && fields[0] != "tcp46" {
            continue;
        }
        if fields[fields.len() - 1] != "LISTEN" {
            continue;
        }
        let Some((host, port)) = fields[3].rsplit_once('.') else {
            continue;
        };
        let Ok(port) = port.parse::<u16>() else {
            continue;
        };
        if port == 0 {
            continue;
        }
        // Link-local IPv6 addresses carry a scope suffix (`%en0`), which
        // `IpAddr` does not accept.
        let host = host.split('%').next().unwrap_or(host);
        let bind = match host {
            "*" => match fields[0] {
                "tcp4" => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
                _ => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
            },
            host => match host.parse::<IpAddr>() {
                Ok(ip) => ip,
                Err(_) => continue,
            },
        };
        result.push((port, bind));
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ipv4_ipv6_and_wildcard() {
        let text = "\
tcp4       0      0  127.0.0.1.18090        *.*                    LISTEN
tcp4       0      0  *.18091                *.*                    LISTEN
tcp6       0      0  ::1.18092              *.*                    LISTEN
tcp46      0      0  *.47811                *.*                    LISTEN
tcp6       0      0  *.88                   *.*                    LISTEN
tcp4       0      0  *.22                   *.*                    LISTEN
tcp4       0      0  127.0.0.1.50000        127.0.0.1.50001        ESTABLISHED
";
        let parsed = parse_netstat(text);
        assert_eq!(
            parsed,
            vec![
                (18090, IpAddr::from([127, 0, 0, 1])),
                (18091, IpAddr::from([0, 0, 0, 0])),
                (18092, IpAddr::from(Ipv6Addr::LOCALHOST)),
                (47811, IpAddr::from(Ipv6Addr::UNSPECIFIED)),
                (88, IpAddr::from(Ipv6Addr::UNSPECIFIED)),
                (22, IpAddr::from([0, 0, 0, 0])),
            ]
        );
    }

    #[test]
    fn strips_ipv6_scope_and_ignores_garbage() {
        let text = "\
tcp6       0      0  fe80::1%lo0.8080       *.*                    LISTEN
udp4       0      0  *.5353                 *.*
tcp4       0      0  not-an-address         *.*                    LISTEN
";
        let parsed = parse_netstat(text);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].0, 8080);
        assert!(parsed[0].1.is_ipv6());
    }
}
