use opsforge_investigate::{collect, config::RunConfig};
use rusqlite::Connection;
use std::fs;

fn schema(db: &Connection, version: u32) {
    db.execute_batch(&format!(
        "PRAGMA user_version={version};
         CREATE TABLE messages(id INTEGER PRIMARY KEY,folderID INTEGER,messageKey INTEGER,date INTEGER,headerMessageID TEXT,deleted INTEGER);
         CREATE TABLE folderLocations(id INTEGER PRIMARY KEY,folderURI TEXT);
         CREATE TABLE messagesText_content(docid INTEGER PRIMARY KEY,c0body,c1subject,c2attachmentNames,c3author,c4recipients);"
    )).expect("schema");
}

#[test]
fn mail_index_import_preserves_wal_ghosts_deleted_rows_and_unknown_transfer_data() {
    let base =
        std::env::temp_dir().join(format!("opsforge-thunderbird-case-{}", std::process::id()));
    fs::create_dir_all(&base).expect("fixture");
    let path = base.join("global-messages-db.sqlite");
    let db = Connection::open(&path).expect("database");
    schema(&db, 30);
    db.execute_batch("PRAGMA journal_mode=WAL; PRAGMA wal_autocheckpoint=0;
        INSERT INTO folderLocations VALUES(1,'mailbox://nobody@Local%20Folders/Sent');
        INSERT INTO messages VALUES(32,1,0,1791549000000000,'sent@example.test',0),(33,NULL,NULL,NULL,'ghost@example.test',0),(34,1,20,0,'deleted@example.test',1),(35,1,30,1,'broken@example.test','not an integer');
        INSERT INTO messagesText_content VALUES(32,'body is not normalized','subject','name, with quotes.txt
second name.txt','sender@example.test','recipient@example.test');").expect("WAL rows");
    let future = base.join("future");
    fs::create_dir(&future).expect("future");
    let future_path = future.join("global-messages-db.sqlite");
    let future_db = Connection::open(&future_path).expect("future database");
    schema(&future_db, 31);
    drop(future_db);
    let mut config = RunConfig::default_for(base.join("cases"));
    config.exfil = false;
    config.timeline = false;
    config.downloads = false;
    config.deep_inventory = false;
    config.live_capture = false;
    config.imports.extend([path.clone(), future_path]);
    let root = collect::run(&config, &|_| {}).expect("case");
    let events: Vec<serde_json::Value> = fs::read_to_string(root.join("normalized/events.jsonl"))
        .expect("events")
        .lines()
        .map(|line| serde_json::from_str(line).expect("event"))
        .collect();
    assert_eq!(events.len(), 3);
    assert_eq!(events[0]["timestamp"], "2026-10-09T12:30:00Z");
    assert!(events[1]["timestamp"].is_null());
    assert_eq!(events[2]["timestamp"], "1970-01-01T00:00:00Z");
    assert!(
        events[0]["detail"]
            .as_str()
            .unwrap()
            .contains("second name.txt")
    );
    assert!(
        events[1]["detail"]
            .as_str()
            .unwrap()
            .contains("\"ghost_reference\":true")
    );
    assert!(
        events[2]["detail"]
            .as_str()
            .unwrap()
            .contains("\"deleted\":1")
    );
    assert!(events.iter().all(|event| event["transfer"].is_null()
        && event["user"].is_null()
        && event["destination"].is_null()));
    assert!(
        !events[0]["detail"]
            .as_str()
            .unwrap()
            .contains("body is not normalized")
    );
    assert_eq!(
        fs::read(root.join("raw/import-000-000000")).expect("raw"),
        fs::read(&path).expect("source")
    );
    assert_eq!(
        fs::read(root.join("raw/import-000-000000-wal")).expect("raw WAL"),
        fs::read(path.with_file_name("global-messages-db.sqlite-wal")).expect("source WAL")
    );
    let coverage = fs::read_to_string(root.join("normalized/coverage.jsonl")).expect("coverage");
    assert!(coverage.contains("invalid Thunderbird index row"));
    assert!(coverage.contains("unsupported Thunderbird search index schema 31"));
    assert!(
        coverage.contains("\"state\":\"unsupported\"") && coverage.contains("\"state\":\"failed\"")
    );
    assert!(coverage.contains("live file copies are not an atomic snapshot"));
    assert!(
        fs::read_to_string(root.join("dashboard/events.js"))
            .expect("dashboard")
            .contains("Cached search-index metadata")
    );
    drop(db);
    fs::remove_dir_all(base).expect("fixture cleanup");
}
