//! SQLite persistence (devices, peers, forwarding rules, inbound references).

use anyhow::{Context, Result};
use lanfp_core::peer::PeerAddr;
use lanfp_core::protocol::RuleState;
use rusqlite::{params, Connection, OptionalExtension, Row};
use std::path::Path;
use std::sync::Mutex;
use std::time::Duration;
use uuid::Uuid;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS device (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  ed25519_pub BLOB NOT NULL,
  cert_der BLOB NOT NULL,
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS peer (
  device_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  ed25519_pub BLOB NOT NULL,
  cert_der BLOB NOT NULL,
  last_addr TEXT,
  paired_at INTEGER NOT NULL,
  last_seen_at INTEGER,
  may_connect INTEGER NOT NULL DEFAULT 0,
  may_dial INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS rule (
  peer_id TEXT NOT NULL REFERENCES peer(device_id) ON DELETE CASCADE,
  rule_id TEXT NOT NULL UNIQUE,
  target_port INTEGER NOT NULL,
  listen_port INTEGER PRIMARY KEY,
  enabled INTEGER NOT NULL DEFAULT 1,
  state TEXT NOT NULL,
  last_error TEXT,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
);

-- Retired: the expose whitelist moved to the config file (`agent.expose_ports`).
DROP TABLE IF EXISTS expose;

CREATE TABLE IF NOT EXISTS inbound_ref (
  peer_id TEXT NOT NULL,
  rule_id TEXT NOT NULL,
  target_port INTEGER NOT NULL,
  peer_listen_port INTEGER NOT NULL,
  first_seen_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL,
  online INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (peer_id, rule_id)
);

CREATE INDEX IF NOT EXISTS rule_peer_idx ON rule(peer_id);
CREATE INDEX IF NOT EXISTS inbound_target_idx ON inbound_ref(target_port);
"#;

#[derive(Debug, Clone)]
pub struct DeviceRecord {
    pub id: Uuid,
    pub name: String,
    pub ed25519_pub: Vec<u8>,
    pub cert_der: Vec<u8>,
    pub created_at: i64,
}

#[derive(Debug, Clone)]
pub struct PeerRecord {
    pub device_id: Uuid,
    pub name: String,
    pub ed25519_pub: Vec<u8>,
    pub cert_der: Vec<u8>,
    pub last_addr: Option<String>,
    pub paired_at: i64,
    pub last_seen_at: Option<i64>,
    /// This device may connect to this machine (set by `lanfp peer grant`).
    pub may_connect: bool,
    /// This machine may dial the device (it authorized this machine).
    pub may_dial: bool,
}

impl PeerRecord {
    pub fn pubkey_array(&self) -> Option<[u8; 32]> {
        self.ed25519_pub.as_slice().try_into().ok()
    }

    /// `<name>@<address>[:port]` display string.
    pub fn display(&self) -> String {
        match &self.last_addr {
            Some(addr) => match PeerAddr::parse(addr) {
                Ok(mut p) => {
                    p.name = Some(lanfp_core::sanitize_device_name(&self.name));
                    p.display()
                }
                Err(_) => format!("{}@{}", self.name, addr),
            },
            None => self.name.clone(),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RuleRecord {
    pub peer_id: Uuid,
    pub rule_id: Uuid,
    pub target_port: u16,
    pub listen_port: u16,
    pub enabled: bool,
    pub state: RuleState,
    pub last_error: Option<String>,
    pub created_at: i64,
    pub updated_at: i64,
}

#[derive(Debug, Clone)]
pub struct InboundRecord {
    pub peer_id: Uuid,
    pub rule_id: Uuid,
    pub target_port: u16,
    pub peer_listen_port: u16,
    pub first_seen_at: i64,
    pub last_seen_at: i64,
    pub online: bool,
}

pub struct Db {
    conn: Mutex<Connection>,
}

impl Db {
    pub fn open(path: &Path) -> Result<Self> {
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let conn =
            Connection::open(path).with_context(|| format!("open database {}", path.display()))?;
        conn.busy_timeout(Duration::from_secs(5))?;
        conn.pragma_update(None, "journal_mode", "WAL")?;
        conn.pragma_update(None, "foreign_keys", "ON")?;
        conn.execute_batch(SCHEMA)
            .context("initialise database schema")?;
        migrate(&conn)?;
        Ok(Self {
            conn: Mutex::new(conn),
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, Connection> {
        self.conn.lock().unwrap_or_else(|e| e.into_inner())
    }

    pub fn upsert_device(&self, device: &DeviceRecord) -> Result<()> {
        self.lock().execute(
            "INSERT INTO device (id, name, ed25519_pub, cert_der, created_at)
             VALUES (?1, ?2, ?3, ?4, ?5)
             ON CONFLICT(id) DO UPDATE SET
               name = excluded.name,
               ed25519_pub = excluded.ed25519_pub,
               cert_der = excluded.cert_der",
            params![
                device.id.to_string(),
                device.name,
                device.ed25519_pub,
                device.cert_der,
                device.created_at
            ],
        )?;
        Ok(())
    }

    pub fn get_device(&self) -> Result<Option<DeviceRecord>> {
        let conn = self.lock();
        let mut stmt =
            conn.prepare("SELECT id, name, ed25519_pub, cert_der, created_at FROM device LIMIT 1")?;
        let row = stmt
            .query_row([], |row| {
                Ok(DeviceRecord {
                    id: parse_uuid(row.get::<_, String>(0)?)?,
                    name: row.get(1)?,
                    ed25519_pub: row.get(2)?,
                    cert_der: row.get(3)?,
                    created_at: row.get(4)?,
                })
            })
            .optional()?;
        Ok(row)
    }

    fn query_peers(&self, filter: &str) -> Result<Vec<PeerRecord>> {
        let conn = self.lock();
        let sql = format!(
            "SELECT device_id, name, ed25519_pub, cert_der, last_addr, paired_at, last_seen_at,
                    may_connect, may_dial
             FROM peer {filter} ORDER BY name COLLATE NOCASE, device_id"
        );
        let mut stmt = conn.prepare(&sql)?;
        let rows = stmt
            .query_map([], row_to_peer)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    /// Every known device, in either direction.
    pub fn list_trust(&self) -> Result<Vec<PeerRecord>> {
        self.query_peers("")
    }

    /// Devices this machine authorized to connect (`lanfp peer list`).
    pub fn list_allowed(&self) -> Result<Vec<PeerRecord>> {
        self.query_peers("WHERE may_connect = 1")
    }

    /// Devices this machine may dial (servers that authorized it).
    pub fn list_dialable(&self) -> Result<Vec<PeerRecord>> {
        self.query_peers("WHERE may_dial = 1")
    }

    /// Keep the historical name: a trust row, in either direction.
    pub fn get_peer(&self, device_id: Uuid) -> Result<Option<PeerRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT device_id, name, ed25519_pub, cert_der, last_addr, paired_at, last_seen_at,
                    may_connect, may_dial
             FROM peer WHERE device_id = ?1",
        )?;
        let row = stmt
            .query_row(params![device_id.to_string()], row_to_peer)
            .optional()?;
        Ok(row)
    }

    /// Keep the historical name: a trust row, in either direction. The TLS
    /// server verifier separately enforces `may_connect`.
    pub fn peer_by_pubkey(&self, pubkey: &[u8]) -> Result<Option<PeerRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT device_id, name, ed25519_pub, cert_der, last_addr, paired_at, last_seen_at,
                    may_connect, may_dial
             FROM peer WHERE ed25519_pub = ?1",
        )?;
        let row = stmt.query_row(params![pubkey], row_to_peer).optional()?;
        Ok(row)
    }

    pub fn upsert_peer(&self, peer: &PeerRecord) -> Result<()> {
        self.lock().execute(
            "INSERT INTO peer (device_id, name, ed25519_pub, cert_der, last_addr, paired_at, last_seen_at,
                               may_connect, may_dial)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)
             ON CONFLICT(device_id) DO UPDATE SET
               name = excluded.name,
               ed25519_pub = excluded.ed25519_pub,
               cert_der = excluded.cert_der,
               last_addr = COALESCE(excluded.last_addr, peer.last_addr),
               paired_at = excluded.paired_at,
               last_seen_at = excluded.last_seen_at,
               may_connect = excluded.may_connect,
               may_dial = excluded.may_dial",
            params![
                peer.device_id.to_string(),
                peer.name,
                peer.ed25519_pub,
                peer.cert_der,
                peer.last_addr,
                peer.paired_at,
                peer.last_seen_at,
                peer.may_connect as i64,
                peer.may_dial as i64
            ],
        )?;
        Ok(())
    }

    pub fn clear_may_connect(&self, device_id: Uuid) -> Result<()> {
        self.lock().execute(
            "UPDATE peer SET may_connect = 0 WHERE device_id = ?1",
            params![device_id.to_string()],
        )?;
        Ok(())
    }

    pub fn delete_peer(&self, device_id: Uuid) -> Result<()> {
        self.lock().execute(
            "DELETE FROM peer WHERE device_id = ?1",
            params![device_id.to_string()],
        )?;
        Ok(())
    }

    pub fn update_peer_seen(&self, device_id: Uuid, addr: Option<&str>, ts: i64) -> Result<()> {
        self.lock().execute(
            "UPDATE peer SET last_seen_at = ?2, last_addr = COALESCE(?3, last_addr)
             WHERE device_id = ?1",
            params![device_id.to_string(), ts, addr],
        )?;
        Ok(())
    }

    /// Refresh the stored display name from the peer's authenticated hello.
    pub fn update_peer_name(&self, device_id: Uuid, name: &str) -> Result<()> {
        self.lock().execute(
            "UPDATE peer SET name = ?2 WHERE device_id = ?1",
            params![device_id.to_string(), name],
        )?;
        Ok(())
    }

    pub fn list_rules(&self) -> Result<Vec<RuleRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT peer_id, rule_id, target_port, listen_port, enabled, state, last_error,
                    created_at, updated_at
             FROM rule ORDER BY listen_port",
        )?;
        let rows = stmt
            .query_map([], row_to_rule)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn get_rule(&self, listen_port: u16) -> Result<Option<RuleRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT peer_id, rule_id, target_port, listen_port, enabled, state, last_error,
                    created_at, updated_at
             FROM rule WHERE listen_port = ?1",
        )?;
        let row = stmt
            .query_row(params![listen_port as i64], row_to_rule)
            .optional()?;
        Ok(row)
    }

    pub fn insert_rule(&self, rule: &RuleRecord) -> Result<()> {
        self.lock().execute(
            "INSERT INTO rule (peer_id, rule_id, target_port, listen_port, enabled, state,
                               last_error, created_at, updated_at)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                rule.peer_id.to_string(),
                rule.rule_id.to_string(),
                rule.target_port as i64,
                rule.listen_port as i64,
                rule.enabled as i64,
                rule.state.as_str(),
                rule.last_error,
                rule.created_at,
                rule.updated_at
            ],
        )?;
        Ok(())
    }

    pub fn delete_rule(&self, listen_port: u16) -> Result<()> {
        self.lock().execute(
            "DELETE FROM rule WHERE listen_port = ?1",
            params![listen_port as i64],
        )?;
        Ok(())
    }

    pub fn update_rule_state(
        &self,
        listen_port: u16,
        state: RuleState,
        error: Option<&str>,
        ts: i64,
    ) -> Result<()> {
        self.lock().execute(
            "UPDATE rule SET state = ?2, last_error = ?3, updated_at = ?4 WHERE listen_port = ?1",
            params![listen_port as i64, state.as_str(), error, ts],
        )?;
        Ok(())
    }

    pub fn list_inbound(&self) -> Result<Vec<InboundRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT peer_id, rule_id, target_port, peer_listen_port, first_seen_at, last_seen_at,
                    online
             FROM inbound_ref ORDER BY target_port, peer_id",
        )?;
        let rows = stmt
            .query_map([], row_to_inbound)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn list_inbound_for_peer(&self, peer_id: Uuid) -> Result<Vec<InboundRecord>> {
        let conn = self.lock();
        let mut stmt = conn.prepare(
            "SELECT peer_id, rule_id, target_port, peer_listen_port, first_seen_at, last_seen_at,
                    online
             FROM inbound_ref WHERE peer_id = ?1",
        )?;
        let rows = stmt
            .query_map(params![peer_id.to_string()], row_to_inbound)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        Ok(rows)
    }

    pub fn upsert_inbound(&self, rec: &InboundRecord) -> Result<()> {
        self.lock().execute(
            "INSERT INTO inbound_ref (peer_id, rule_id, target_port, peer_listen_port,
                                      first_seen_at, last_seen_at, online)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)
             ON CONFLICT(peer_id, rule_id) DO UPDATE SET
               target_port = excluded.target_port,
               peer_listen_port = excluded.peer_listen_port,
               last_seen_at = excluded.last_seen_at,
               online = excluded.online",
            params![
                rec.peer_id.to_string(),
                rec.rule_id.to_string(),
                rec.target_port as i64,
                rec.peer_listen_port as i64,
                rec.first_seen_at,
                rec.last_seen_at,
                rec.online as i64
            ],
        )?;
        Ok(())
    }

    pub fn delete_inbound(&self, peer_id: Uuid, rule_id: Uuid) -> Result<()> {
        self.lock().execute(
            "DELETE FROM inbound_ref WHERE peer_id = ?1 AND rule_id = ?2",
            params![peer_id.to_string(), rule_id.to_string()],
        )?;
        Ok(())
    }

    pub fn touch_peer_inbound(&self, peer_id: Uuid, ts: i64) -> Result<()> {
        self.lock().execute(
            "UPDATE inbound_ref SET last_seen_at = ?2, online = 1 WHERE peer_id = ?1",
            params![peer_id.to_string(), ts],
        )?;
        Ok(())
    }

    pub fn mark_all_inbound_offline(&self, ts: i64) -> Result<()> {
        self.lock().execute(
            "UPDATE inbound_ref SET online = 0, last_seen_at = ?1",
            params![ts],
        )?;
        Ok(())
    }

    pub fn mark_peer_inbound_offline(&self, peer_id: Uuid, ts: i64) -> Result<()> {
        self.lock().execute(
            "UPDATE inbound_ref SET online = 0, last_seen_at = ?2 WHERE peer_id = ?1",
            params![peer_id.to_string(), ts],
        )?;
        Ok(())
    }

    pub fn delete_inbound_for_peer(&self, peer_id: Uuid) -> Result<()> {
        self.lock().execute(
            "DELETE FROM inbound_ref WHERE peer_id = ?1",
            params![peer_id.to_string()],
        )?;
        Ok(())
    }

    #[allow(dead_code)]
    pub fn count_rules(&self) -> Result<usize> {
        let conn = self.lock();
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM rule", [], |r| r.get(0))?;
        Ok(n as usize)
    }
}

fn ensure_column(conn: &Connection, table: &str, column: &str, ddl: &str) -> Result<()> {
    let mut stmt = conn.prepare(&format!("PRAGMA table_info({table})"))?;
    let exists = stmt
        .query_map([], |row| row.get::<_, String>(1))?
        .any(|name| name.map(|name| name == column).unwrap_or(false));
    if !exists {
        conn.execute_batch(ddl)?;
    }
    Ok(())
}

fn migrate(conn: &Connection) -> Result<()> {
    // Old databases have mutual `peer` rows; giving both direction flags the
    // default of 1 preserves their previous behaviour. Fresh tables declare
    // both columns with a default of 0 and the code sets them explicitly.
    ensure_column(
        conn,
        "peer",
        "may_connect",
        "ALTER TABLE peer ADD COLUMN may_connect INTEGER NOT NULL DEFAULT 1",
    )?;
    ensure_column(
        conn,
        "peer",
        "may_dial",
        "ALTER TABLE peer ADD COLUMN may_dial INTEGER NOT NULL DEFAULT 1",
    )?;
    conn.pragma_update(None, "user_version", 1)?;
    Ok(())
}

fn parse_uuid(s: String) -> rusqlite::Result<Uuid> {
    Uuid::parse_str(&s).map_err(|e| {
        rusqlite::Error::FromSqlConversionFailure(0, rusqlite::types::Type::Text, Box::new(e))
    })
}

fn row_to_peer(row: &Row<'_>) -> rusqlite::Result<PeerRecord> {
    Ok(PeerRecord {
        device_id: parse_uuid(row.get::<_, String>(0)?)?,
        name: row.get(1)?,
        ed25519_pub: row.get(2)?,
        cert_der: row.get(3)?,
        last_addr: row.get(4)?,
        paired_at: row.get(5)?,
        last_seen_at: row.get(6)?,
        may_connect: row.get::<_, i64>(7)? != 0,
        may_dial: row.get::<_, i64>(8)? != 0,
    })
}

fn row_to_rule(row: &Row<'_>) -> rusqlite::Result<RuleRecord> {
    let state: String = row.get(5)?;
    Ok(RuleRecord {
        peer_id: parse_uuid(row.get::<_, String>(0)?)?,
        rule_id: parse_uuid(row.get::<_, String>(1)?)?,
        target_port: row.get::<_, i64>(2)? as u16,
        listen_port: row.get::<_, i64>(3)? as u16,
        enabled: row.get::<_, i64>(4)? != 0,
        state: RuleState::parse(&state),
        last_error: row.get(6)?,
        created_at: row.get(7)?,
        updated_at: row.get(8)?,
    })
}

fn row_to_inbound(row: &Row<'_>) -> rusqlite::Result<InboundRecord> {
    Ok(InboundRecord {
        peer_id: parse_uuid(row.get::<_, String>(0)?)?,
        rule_id: parse_uuid(row.get::<_, String>(1)?)?,
        target_port: row.get::<_, i64>(2)? as u16,
        peer_listen_port: row.get::<_, i64>(3)? as u16,
        first_seen_at: row.get(4)?,
        last_seen_at: row.get(5)?,
        online: row.get::<_, i64>(6)? != 0,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;

    fn db() -> (TempDir, Db) {
        let dir = TempDir::new().unwrap();
        let db = Db::open(&dir.path().join("test.db")).unwrap();
        (dir, db)
    }

    fn peer(name: &str, addr: &str) -> PeerRecord {
        PeerRecord {
            device_id: Uuid::new_v4(),
            name: name.into(),
            ed25519_pub: vec![1u8; 32],
            cert_der: vec![2u8; 4],
            last_addr: Some(addr.into()),
            paired_at: 100,
            last_seen_at: Some(200),
            may_connect: true,
            may_dial: true,
        }
    }

    #[test]
    fn device_round_trip() {
        let (_dir, db) = db();
        assert!(db.get_device().unwrap().is_none());
        let dev = DeviceRecord {
            id: Uuid::new_v4(),
            name: "box".into(),
            ed25519_pub: vec![3u8; 32],
            cert_der: vec![4u8; 8],
            created_at: 1,
        };
        db.upsert_device(&dev).unwrap();
        let got = db.get_device().unwrap().unwrap();
        assert_eq!(got.id, dev.id);
        assert_eq!(got.name, "box");
        assert_eq!(got.cert_der, dev.cert_der);
    }

    #[test]
    fn peer_round_trip_and_lookup_by_pubkey() {
        let (_dir, db) = db();
        let mut p = peer("mac-mini", "192.168.8.10:47811");
        p.ed25519_pub = vec![9u8; 32];
        db.upsert_peer(&p).unwrap();
        assert_eq!(db.list_trust().unwrap().len(), 1);
        let got = db.get_peer(p.device_id).unwrap().unwrap();
        assert_eq!(got.display(), "mac-mini@192.168.8.10");
        assert_eq!(
            db.peer_by_pubkey(&[9u8; 32]).unwrap().unwrap().device_id,
            p.device_id
        );
        db.update_peer_seen(p.device_id, Some("192.168.8.11:47811"), 300)
            .unwrap();
        db.update_peer_name(p.device_id, "renamed").unwrap();
        assert_eq!(db.get_peer(p.device_id).unwrap().unwrap().name, "renamed");
        let got = db.get_peer(p.device_id).unwrap().unwrap();
        assert_eq!(got.last_seen_at, Some(300));
        assert_eq!(got.display(), "renamed@192.168.8.11");
    }

    #[test]
    fn rules_crud() {
        let (_dir, db) = db();
        let p = peer("box", "10.0.0.2:47811");
        db.upsert_peer(&p).unwrap();
        let rule = RuleRecord {
            peer_id: p.device_id,
            rule_id: Uuid::new_v4(),
            target_port: 3000,
            listen_port: 3000,
            enabled: true,
            state: RuleState::Active,
            last_error: None,
            created_at: 1,
            updated_at: 1,
        };
        db.insert_rule(&rule).unwrap();
        assert_eq!(db.list_rules().unwrap().len(), 1);
        assert_eq!(db.count_rules().unwrap(), 1);
        db.update_rule_state(3000, RuleState::TargetGone, Some("gone"), 2)
            .unwrap();
        let got = db.get_rule(3000).unwrap().unwrap();
        assert_eq!(got.state, RuleState::TargetGone);
        assert_eq!(got.last_error.as_deref(), Some("gone"));
        db.delete_rule(3000).unwrap();
        assert!(db.get_rule(3000).unwrap().is_none());
    }

    #[test]
    fn inbound_upsert_and_offline() {
        let (_dir, db) = db();
        let p = peer("box", "10.0.0.2:47811");
        db.upsert_peer(&p).unwrap();
        let rule_id = Uuid::new_v4();
        db.upsert_inbound(&InboundRecord {
            peer_id: p.device_id,
            rule_id,
            target_port: 8080,
            peer_listen_port: 8080,
            first_seen_at: 1,
            last_seen_at: 2,
            online: true,
        })
        .unwrap();
        let rows = db.list_inbound().unwrap();
        assert_eq!(rows.len(), 1);
        assert!(rows[0].online);
        db.mark_peer_inbound_offline(p.device_id, 3).unwrap();
        let rows = db.list_inbound().unwrap();
        assert!(!rows[0].online);
        assert_eq!(rows[0].last_seen_at, 3);
        db.delete_inbound(p.device_id, rule_id).unwrap();
        assert!(db.list_inbound().unwrap().is_empty());
    }

    #[test]
    fn trust_directions_are_independent() {
        let (_dir, db) = db();
        let mut p = peer("laptop", "127.0.0.1:5000");
        p.may_connect = true;
        p.may_dial = false;
        db.upsert_peer(&p).unwrap();
        assert_eq!(db.list_allowed().unwrap().len(), 1);
        assert!(db.list_dialable().unwrap().is_empty());
        assert_eq!(db.list_trust().unwrap().len(), 1);

        p.may_connect = false;
        p.may_dial = true;
        db.upsert_peer(&p).unwrap();
        assert!(db.list_allowed().unwrap().is_empty());
        assert_eq!(db.list_dialable().unwrap().len(), 1);

        p.may_connect = true;
        db.upsert_peer(&p).unwrap();
        db.clear_may_connect(p.device_id).unwrap();
        assert!(db.list_allowed().unwrap().is_empty());
        assert_eq!(db.list_dialable().unwrap().len(), 1);
        db.delete_peer(p.device_id).unwrap();
        assert!(db.list_trust().unwrap().is_empty());
    }

    #[test]
    fn drops_retired_expose_table() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE expose (
                   port INTEGER PRIMARY KEY,
                   created_at INTEGER NOT NULL
                 );
                 INSERT INTO expose (port, created_at) VALUES (3000, 0);",
            )
            .unwrap();
        }
        let _db = Db::open(&path).unwrap();
        let exists: i64 = {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.query_row(
                "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'expose'",
                [],
                |r| r.get(0),
            )
        }
        .unwrap();
        assert_eq!(exists, 0);
    }

    #[test]
    fn migrates_old_peer_rows_as_mutual() {
        let dir = TempDir::new().unwrap();
        let path = dir.path().join("old.db");
        {
            let conn = rusqlite::Connection::open(&path).unwrap();
            conn.execute_batch(
                "CREATE TABLE peer (
                   device_id TEXT PRIMARY KEY,
                   name TEXT NOT NULL,
                   ed25519_pub BLOB NOT NULL,
                   cert_der BLOB NOT NULL,
                   last_addr TEXT,
                   paired_at INTEGER NOT NULL,
                   last_seen_at INTEGER
                 );
                 INSERT INTO peer VALUES (
                   '11111111-1111-4111-8111-111111111111',
                   'old-peer', x'01', x'02', '10.0.0.2:47811', 1, 2
                 );",
            )
            .unwrap();
        }
        let db = Db::open(&path).unwrap();
        let peers = db.list_trust().unwrap();
        assert_eq!(peers.len(), 1);
        assert!(peers[0].may_connect);
        assert!(peers[0].may_dial);
        assert_eq!(db.list_allowed().unwrap().len(), 1);
        assert_eq!(db.list_dialable().unwrap().len(), 1);
    }

    #[test]
    fn peer_delete_cascades_rules() {
        let (_dir, db) = db();
        let p = peer("box", "10.0.0.2:47811");
        db.upsert_peer(&p).unwrap();
        db.insert_rule(&RuleRecord {
            peer_id: p.device_id,
            rule_id: Uuid::new_v4(),
            target_port: 1,
            listen_port: 2,
            enabled: true,
            state: RuleState::Active,
            last_error: None,
            created_at: 1,
            updated_at: 1,
        })
        .unwrap();
        db.lock()
            .execute(
                "DELETE FROM peer WHERE device_id = ?1",
                params![p.device_id.to_string()],
            )
            .unwrap();
        assert_eq!(db.count_rules().unwrap(), 0);
    }
}
