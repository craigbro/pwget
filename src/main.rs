use pwsafer::PwsafeReader;
use std::fs::File;
use std::io::BufReader;

/* From: https://github.com/pwsafe/pwsafe/blob/master/docs/formatV3.txt */
#[repr(u8)]
#[derive(Debug, PartialEq, PartialOrd, Eq)]
enum FieldType {
    Group = 2u8,
    Title = 3u8,
    Username = 4u8,
    Notes = 0x05u8,
    Password = 0x06u8,
    Url = 0x0du8,
    Email = 0x14u8,
    EndOfRecord = 0xffu8,
}

#[derive(Debug)]
struct Entry {
    group: Option<String>,
    title: String,
    password: String,
    username: Option<String>,
    notes: Option<String>,
    url: Option<String>,
    email: Option<String>,
}

trait EntryReader {
    fn read_entry(&mut self) -> Option<Entry>;
}

impl<R: std::io::Read> EntryReader for PwsafeReader<R> {
    // push type,data tuples onto hashmap keyed on field type,
    // then create struct by
    // searching for the desired field in vec
    // use PwsafeRecordField::new(type,data) ...

    fn read_entry(&mut self) -> Option<Entry> {
        let mut title = String::from("");
        let mut password = String::from("");
        let mut group = None;
        let mut username = None;
        let mut notes = None;
        let mut url = None;
        let mut email = None;

        while let Some((field_type, field_data)) = self.read_field().unwrap() {
            if field_type == FieldType::Title as u8 {
                title = String::from_utf8(field_data).unwrap();
            } else if field_type == FieldType::Group as u8 {
                group = Some(String::from_utf8(field_data).unwrap());
            } else if field_type == FieldType::Password as u8 {
                password = String::from_utf8(field_data).unwrap();
            } else if field_type == FieldType::Username as u8 {
                username = Some(String::from_utf8(field_data).unwrap());
            } else if field_type == FieldType::Notes as u8 {
                notes = Some(String::from_utf8(field_data).unwrap());
            } else if field_type == FieldType::Email as u8 {
                email = Some(String::from_utf8(field_data).unwrap());
            } else if field_type == FieldType::Url as u8 {
                url = Some(String::from_utf8(field_data).unwrap());
            } else if field_type == FieldType::EndOfRecord as u8 {
                return Some(Entry {
                    group,
                    title,
                    password,
                    username,
                    notes,
                    url,
                    email,
                });
            }
        }
    }
}

fn main() {
    /* Implemntation Plan
    - get file, title, group
    - get output spec (password, or entire entry)
    - get db password from user, interactively
    - decrypt and loop until find entry
    - output as specified
    */

    let filename = "test.pwsafe3";
    let file = BufReader::new(File::open(filename).unwrap());
    let mut db = PwsafeReader::new(file, b"no kind of atmosphere").unwrap();
    /* let version = db.read_version().unwrap();
    println!("Version is {:x}", version); */
    while let Some(entry) = db.read_entry() {
        println!("Read entry{:?}", entry);
    }
    db.verify().unwrap();
}
