use pwsafer::{PwsafeReader, PwsafeRecordField};
use std::fs::File;
use std::io::BufReader;

#[derive(Debug)]
struct PwsafeRecord {
    fields: Vec<PwsafeRecordField>,
}

impl PwsafeRecord {
    fn title(&self) -> Option<&String> {
        return match self
            .fields
            .iter()
            .find(|f| matches!(f, PwsafeRecordField::Title(..)))
        {
            Some(PwsafeRecordField::Title(t)) => Some(t),
            _ => None,
        };
    }
    fn group(&self) -> Option<&String> {
        return if let Some(PwsafeRecordField::Group(g)) = self
            .fields
            .iter()
            .find(|f| matches!(f, PwsafeRecordField::Group(..)))
        {
            Some(g)
        } else {
            None
        };
    }
    fn password(&self) -> Option<&String> {
        return match self
            .fields
            .iter()
            .find(|f| matches!(f, PwsafeRecordField::Password(..)))
        {
            Some(PwsafeRecordField::Password(t)) => Some(t),
            _ => None,
        };
    }
    fn notes(&self) -> Option<&String> {
        return match self
            .fields
            .iter()
            .find(|f| matches!(f, PwsafeRecordField::Notes(..)))
        {
            Some(PwsafeRecordField::Notes(t)) => Some(t),
            _ => None,
        };
    }
}

trait PwsafeRecordReader {
    fn read_record(&mut self) -> Option<PwsafeRecord>;
    //    fn filter_records(&mut self, pattern: String) -> Vec<PwsafeRecord>;
}

impl<R: std::io::Read> PwsafeRecordReader for PwsafeReader<R> {
    fn read_record(&mut self) -> Option<PwsafeRecord> {
        let mut rec = PwsafeRecord { fields: Vec::new() };

        while let Some((field_type, field_data)) = self.read_field().unwrap() {
            let result = pwsafer::PwsafeRecordField::new(field_type, field_data);
            match result {
                Ok(field) => match field {
                    PwsafeRecordField::EndOfRecord => return Some(rec),
                    _ => rec.fields.push(field),
                },
                Err(why) => eprintln!("Error reading field: {}", why),
            };
        }
        if !rec.fields.is_empty() {
            eprintln!("Incomplete record");
        }
        return None;
    }
}

/* use clap to build cmdline interface

The tasks we want this tool to accomplish:

1. search, list matching entries, without revealing secrets
  - select by uuid or group.title fragment match
  - show uuid, group.title, username, email, url
2. pull, select a entry and put it's password in clipboard
  - select, and if only a single match, do it
  - otherwise, list, and then return non-zero
3. show, select a entry and print it entirely
  - select, and if only a single match, do it
  - show same as seach, but include, password and notes

Allow specification of file, but read from PWSAFE_DB envvar if present
  - env::var
Prompt for password, use rpassword crate

 */
fn main() {
    // parse command
    // get file
    // get password

    // get records
    // operate on record(s)

    let filename = "test.pwsafe3";
    let file = BufReader::new(File::open(filename).unwrap());
    let mut db = PwsafeReader::new(file, b"no kind of atmosphere").unwrap();
    /* let version = db.read_version().unwrap();
    println!("Version is {:x}", version); */
    while let Some(entry) = db.read_record() {
        println!(
            "{:?}, {:?}, {:?}",
            entry.group(),
            entry.title(),
            entry.password()
        );
    }
    db.verify().unwrap();
}
