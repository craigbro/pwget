use clap::{Parser, Subcommand};
use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;
use pwsafer::{PwsafeReader, PwsafeRecordField};
use rpassword::prompt_password;
use serde::{Deserialize, Serialize};
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use uuid::Uuid;

/// A transient structure to hold the set of pwsafe fields
#[derive(Debug)]
struct PwsafeRecord {
    fields: Vec<PwsafeRecordField>,
    errors: Vec<String>,
}

/// A secure representations of a record
#[derive(Serialize, Deserialize, Debug)]
struct SecureEntry {
    uuid: String,
    group: Option<String>,
    title: Option<String>,
    username: Option<String>,
    url: Option<String>,
    email_address: Option<String>,
}

/// A full representations of a record, as we support them.  This is
/// does not support all field types
#[derive(Serialize, Deserialize, Debug)]
struct Entry {
    uuid: String,
    group: Option<String>,
    title: Option<String>,
    password: Option<String>,
    username: Option<String>,
    url: Option<String>,
    email_address: Option<String>,
    notes: Option<String>,
    errors: Vec<String>,
}

impl PwsafeRecord {
    fn uuid(&self) -> Option<Uuid> {
        return match self
            .fields
            .iter()
            .find(|f| matches!(f, PwsafeRecordField::Uuid(..)))
        {
            Some(PwsafeRecordField::Uuid(t)) => Some(Uuid::from_bytes(*t)),
            _ => None,
        };
    }
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

    fn username(&self) -> Option<&String> {
        return match self
            .fields
            .iter()
            .find(|f| matches!(f, PwsafeRecordField::Username(..)))
        {
            Some(PwsafeRecordField::Username(t)) => Some(t),
            _ => None,
        };
    }

    fn email_address(&self) -> Option<&String> {
        return match self
            .fields
            .iter()
            .find(|f| matches!(f, PwsafeRecordField::EmailAddress(..)))
        {
            Some(PwsafeRecordField::EmailAddress(t)) => Some(t),
            _ => None,
        };
    }

    fn url(&self) -> Option<&String> {
        return match self
            .fields
            .iter()
            .find(|f| matches!(f, PwsafeRecordField::Url(..)))
        {
            Some(PwsafeRecordField::Url(t)) => Some(t),
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

    fn as_secure_entry(&self) -> SecureEntry {
        SecureEntry {
            uuid: self.uuid().unwrap().hyphenated().to_string(),
            group: self.group().cloned(),
            title: self.title().cloned(),
            username: self.username().cloned(),
            email_address: self.email_address().cloned(),
            url: self.url().cloned(),
        }
    }

    fn as_entry(&self) -> Entry {
        Entry {
            uuid: self.uuid().unwrap().hyphenated().to_string(),
            group: self.group().cloned(),
            title: self.title().cloned(),
            password: self.password().cloned(),
            username: self.username().cloned(),
            email_address: self.email_address().cloned(),
            url: self.url().cloned(),
            notes: self.notes().cloned(),
            errors: self.errors.to_owned(),
        }
    }

    fn to_json(&self, reveal: bool) -> String {
        if reveal {
            serde_json::to_string(&self.as_entry()).unwrap()
        } else {
            serde_json::to_string(&self.as_secure_entry()).unwrap()
        }
    }
    // Returns true if <group>.<title> or <uuid> of the entry contains the `term` as a substring. <uuid> is in hyphenated string format.
    fn search(&self, term: String) -> bool {
        let empty = String::from("");
        let ts = term.as_str();
        let uuid = self.uuid().unwrap().hyphenated().to_string();
        let name = format!(
            "{}.{}",
            self.group().unwrap_or(&empty),
            self.title().unwrap_or(&empty)
        );
        name.contains(ts) || uuid.contains(ts)
    }

    // Returns true if <group>.<title> or <uuid> matches `term` exactly.
    // <uuid> is in hypthenated string format
    fn matchp(&self, term: String) -> bool {
        let empty = String::from("");
        let ts = term.as_str();
        let uuid = self.uuid().unwrap().hyphenated().to_string();
        let name = format!(
            "{}.{}",
            self.group().unwrap_or(&empty),
            self.title().unwrap_or(&empty)
        );
        name == ts || uuid == ts
    }
}

trait PwsafeRecordReader {
    fn read_record(&mut self) -> Option<PwsafeRecord>;
    //    fn filter_records(&mut self, pattern: String) -> Vec<PwsafeRecord>;
    fn records(&mut self) -> Vec<PwsafeRecord>;
}

impl<R: std::io::Read> PwsafeRecordReader for PwsafeReader<R> {
    fn read_record(&mut self) -> Option<PwsafeRecord> {
        let mut rec = PwsafeRecord {
            fields: Vec::new(),
            errors: Vec::new(),
        };

        while let Some((field_type, field_data)) = self.read_field().unwrap() {
            let result = pwsafer::PwsafeRecordField::new(field_type, field_data);
            match result {
                Ok(field) => match field {
                    PwsafeRecordField::EndOfRecord => return Some(rec),
                    _ => rec.fields.push(field),
                },
                Err(why) => rec
                    .errors
                    .push(format!("Error reading field({}): {}", field_type, why)),
            };
        }
        if !rec.fields.is_empty() {
            eprintln!("Incomplete record");
        }
        None
    }

    fn records(&mut self) -> Vec<PwsafeRecord> {
        let mut records = Vec::new();
        while let Some(record) = self.read_record() {
            records.push(record);
        }
        records
    }
}

#[derive(Parser, Debug)]
#[command(author, version, about, long_about = None)]
struct Cli {
    #[arg(
        long,
        short,
        env = "PWSAFE_DB",
        default_value = "pwsafe3.db",
        help = "The pwsafe3 database file to read."
    )]
    dbfile: PathBuf,

    #[command(subcommand)]
    command: Commands,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// List entries on stdout, in JSONL
    List {
        /// A substring matched against `<group>.<title>` or <uuid> of the entry
        term: Option<String>,
        /// include password and notes in the output
        #[arg(long, short, default_value = "false")]
        reveal: bool,
    },
    /// Retrieve a password for an entry.
    Pass {
        /// A string matched against `<group>.<title>` or `<uuid>` of
        /// the entry. If a perfect match is found, that is used
        /// immediately.  Otherwise, we will look for a substring
        /// match.  If there are multiple matches, than entries will
        /// be listed and no password will be retrieved and will exit
        /// with a 1.
        term: String,

        /// print the password to stdout
        #[arg(long, short, default_value = "false")]
        print: bool,
    },
}

fn password_to_clipboard(pass: String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(pass).ok();
}

fn main() {
    let cli = Cli::parse();

    let dbfile = match File::open(&cli.dbfile) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "Unable to open pwsafe3 db file {}: {}",
                cli.dbfile.to_str().unwrap(),
                e
            );
            std::process::exit(1);
        }
    };

    let password = match prompt_password("Password: ") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Unable to read password");
            std::process::exit(1);
        }
    };

    let mut db = match PwsafeReader::new(BufReader::new(dbfile), password.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error reading {}: {}", cli.dbfile.to_str().unwrap(), e);
            std::process::exit(1);
        }
    };

    // get records
    // operate on record(s)
    match &cli.command {
        Commands::List { term, reveal } => {
            if let Some(substr) = term {
                for record in db
                    .records()
                    .iter()
                    .filter(|&e| e.search(substr.to_string()))
                {
                    println!("{}", &record.to_json(*reveal))
                }
            } else {
                for record in db.records() {
                    println!("{}", &record.to_json(*reveal))
                }
            }
            std::process::exit(0)
        }
        Commands::Pass { term, print } => {
            let recs = db.records();

            // look for an exact "group.title" match first
            // then look for any entries containing our term
            if let Some(exact) = recs.iter().find(|&e| e.matchp(term.clone())) {
                if *print {
                    println!("{}", exact.password().unwrap());
                } else {
                    password_to_clipboard(exact.password().unwrap().to_string());
                }
                std::process::exit(0);
            } else {
                let matches: Vec<&PwsafeRecord> =
                    recs.iter().filter(|&e| e.search(term.clone())).collect();

                if matches.is_empty() {
                    eprintln!("No matches found.");
                    std::process::exit(1);
                } else if matches.len() > 1 {
                    eprintln!("Multiple matches, please be more specific: ");
                    for record in matches {
                        eprintln!("{}", &record.to_json(false))
                    }
                    std::process::exit(1);
                } else if *print {
                    println!("{}", matches[0].password().unwrap());
                } else {
                    password_to_clipboard(matches[0].password().unwrap().to_string());
                }
                std::process::exit(0);
            }
        }
    }
}
