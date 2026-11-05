//! Plain-text table rendering.

/// Print an aligned table. Headers are expected to be uppercase.
pub fn print_table(headers: &[&str], rows: &[Vec<String>]) {
    let mut widths: Vec<usize> = headers.iter().map(|h| h.chars().count()).collect();
    for row in rows {
        for (i, cell) in row.iter().enumerate() {
            if i < widths.len() {
                widths[i] = widths[i].max(cell.chars().count());
            }
        }
    }

    let mut line = String::new();
    for (i, header) in headers.iter().enumerate() {
        if i > 0 {
            line.push_str("   ");
        }
        line.push_str(header);
        for _ in header.chars().count()..widths[i] {
            line.push(' ');
        }
    }
    println!("{}", line.trim_end());

    for row in rows {
        let mut line = String::new();
        for (i, cell) in row.iter().enumerate() {
            if i > 0 {
                line.push_str("   ");
            }
            line.push_str(cell);
            if i + 1 < row.len() {
                for _ in cell.chars().count()..widths[i] {
                    line.push(' ');
                }
            }
        }
        println!("{}", line.trim_end());
    }
}

/// Render `Vec<u16>` as `3000,3001` (empty becomes `-`).
pub fn join_ports(ports: &[u16]) -> String {
    if ports.is_empty() {
        "-".into()
    } else {
        ports
            .iter()
            .map(|p| p.to_string())
            .collect::<Vec<_>>()
            .join(",")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn joins_ports() {
        assert_eq!(join_ports(&[]), "-");
        assert_eq!(join_ports(&[3000]), "3000");
        assert_eq!(join_ports(&[3000, 3001]), "3000,3001");
    }
}
