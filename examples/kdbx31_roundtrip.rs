use std::io::Cursor;

use keepass_rs::model::core::node::NodeId;
use keepass_rs::model::core::security::ProtectedString;
use keepass_rs::model::db::database::{Database, DatabaseVersion};
use keepass_rs::model::entry::Entry;
use keepass_rs::model::group::Group;
use keepass_rs::{open_database, save_database, CompositeKey};
use sha2::{Digest, Sha256};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let mut database = Database::new(DatabaseVersion::KDBX31);
    let root_id = NodeId::new_uuid();
    let mut root = Group::new(root_id);
    root.title = "Peplos compatibility check".into();

    let entry_id = NodeId::new_uuid();
    let mut entry = Entry::new(entry_id);
    entry.title = "Synthetic entry".into();
    entry.username = ProtectedString::new_plain("test-user");
    entry.password = ProtectedString::new_protected("synthetic-password");
    root.add_child_entry(entry_id);

    database.entries.insert(entry_id, entry);
    database.groups.insert(root_id, root);
    database.root_group_id = Some(root_id);

    let password = b"synthetic-master-key";
    let key = CompositeKey::new().with_password(password);
    let password_component = Sha256::digest(password);
    let expected_composite_key = Sha256::digest(password_component);
    assert_eq!(
        key.build_raw_key().as_slice(),
        expected_composite_key.as_slice()
    );
    let mut first_save = Vec::new();
    save_database(&mut first_save, &database, &key)?;

    let opened = open_database(Cursor::new(first_save), &key)?;
    assert_eq!(opened.version, DatabaseVersion::KDBX31);
    assert_eq!(opened.entry_count(), 1);
    assert_eq!(
        opened
            .kdf_parameters
            .as_ref()
            .and_then(|kdf| kdf.get_uint64("R")),
        Some(60_000)
    );

    let mut second_save = Vec::new();
    save_database(&mut second_save, &opened, &key)?;
    let reopened = open_database(Cursor::new(second_save), &key)?;
    assert_eq!(reopened.entry_count(), 1);
    assert_eq!(
        reopened
            .kdf_parameters
            .as_ref()
            .and_then(|kdf| kdf.get_uint64("R")),
        Some(60_000)
    );

    println!("KDBX 3.1 synthetic save/open/save/open: OK");
    Ok(())
}
