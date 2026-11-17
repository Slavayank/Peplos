use keepass_rs::{open_database, save_database, CompositeKey, EncryptionAlgorithm};

// Synthetic fixture created with KeePass 2.54 and the password below.
#[test]
fn opens_and_resaves_a_database_created_by_keepass() {
    let key = CompositeKey::new().with_password(b"fixture-12345");
    let original = include_bytes!("fixtures/keepass-generated.bin");
    let database = open_database(original.as_slice(), &key).unwrap();
    let entry = database.entries.values().next().unwrap();
    assert_eq!(entry.title, "KeePass fixture");
    assert_eq!(entry.password.as_str(), "fixture-secret");
    assert_eq!(database.encryption_algorithm, EncryptionAlgorithm::AesRijndael);
    let mut saved = Vec::new();
    save_database(&mut saved, &database, &key).unwrap();
    let again = open_database(saved.as_slice(), &key).unwrap();
    assert_eq!(again.entries.values().next().unwrap().password.as_str(), "fixture-secret");
    let mut corrupted = saved.clone();
    corrupted[20] ^= 1;
    assert!(open_database(corrupted.as_slice(), &key).is_err());
}
