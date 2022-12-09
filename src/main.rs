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
        return match self
            .fields
            .iter()
            .find(|f| matches!(f, PwsafeRecordField::Group(..)))
        {
            Some(PwsafeRecordField::Group(g)) => Some(g),
            _ => None,
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

/* use clap to build cmdline interface */
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
