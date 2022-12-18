use clap::{Parser, Subcommand};
use pwsafer::{PwsafeReader, PwsafeRecordField};
use rpassword::prompt_password;
use std::fs::File;
use std::io::BufReader;
use std::path::PathBuf;
use uuid::Uuid;

use clipboard::ClipboardContext;
use clipboard::ClipboardProvider;

fn password_to_clipboard(pass: String) {
    let mut ctx: ClipboardContext = ClipboardProvider::new().unwrap();
    ctx.set_contents(pass).ok();
}

#[derive(Debug)]
struct PwsafeRecord {
    fields: Vec<PwsafeRecordField>,
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
    #[allow(dead_code)]
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

    fn to_csv(&self) -> String {
        let empty = String::from("");
        format!(
            "'{}','{}','{}'",
            self.uuid().unwrap().hyphenated(),
            self.group().unwrap_or(&empty),
            self.title().unwrap_or(&empty)
        )
    }

    fn search(&self, term: Option<&String>) -> bool {
        let empty = String::from("");
        match term {
            Some(term) => {
                let ts = term.as_str();
                let name = format!(
                    "{}.{}",
                    self.group().unwrap_or(&empty),
                    self.title().unwrap_or(&empty)
                );
                name.contains(ts)
            }

            None => true,
        }
    }

    fn matchp(&self, term: Option<&String>) -> bool {
        let empty = String::from("");
        match term {
            Some(term) => {
                let ts = term.as_str();
                let name = format!(
                    "{}.{}",
                    self.group().unwrap_or(&empty),
                    self.title().unwrap_or(&empty)
                );
                name == ts
            }

            None => true,
        }
    }
}

trait PwsafeRecordReader {
    fn read_record(&mut self) -> Option<PwsafeRecord>;
    //    fn filter_records(&mut self, pattern: String) -> Vec<PwsafeRecord>;
    fn records(&mut self) -> Vec<PwsafeRecord>;
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
                Err(why) => eprintln!("Error reading field({}): {}", field_type, why),
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

/* use clap to build cmdline interface

The tasks we want this tool to accomplish:

1. search, list matching entries, without revealing secrets
  - select by uuid or group.title fragment match
  - show uuid, group.title, username, email, url
2. pull, select a entry and put it's password in clipboard
  - select, and if only a single match, do it
  - otherwise, list, and then return non-zero

Allow specification of file, but read from PWSAFE_DB envvar if present
  - env::var
Prompt for password, use rpassword crate

 */

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
    /// Search for entries, printing a list of matches
    Search { term: String },
    /// Retrieve a password for a single entry
    Password {
        /// matched against <group>.<title> of the entry. If a perfect
        /// match is found, that is used. otherwise, will look for a
        /// partial.  If multiple matches, than entries will be listed
        /// and no password will be retrieved.
        term: String,

        #[arg(long, short, default_value = "false")]
        print: bool,
    },
    /// Show the full contents of maching entries
    Show { term: String },
}

fn main() {
    // parse command
    let cli = Cli::parse();

    let dbfile = match File::open(&cli.dbfile) {
        Ok(v) => v,
        Err(e) => {
            eprintln!(
                "Unable to open pwsafe3 db file {}: {}",
                cli.dbfile.to_str().unwrap(),
                e
            );
            return;
        }
    };

    let password = match prompt_password("Password: ") {
        Ok(p) => p,
        Err(_) => {
            eprintln!("Unable to read password");
            return;
        }
    };

    let mut db = match PwsafeReader::new(BufReader::new(dbfile), password.as_bytes()) {
        Ok(v) => v,
        Err(e) => {
            eprintln!("Error reading {}: {}", cli.dbfile.to_str().unwrap(), e);
            return;
        }
    };

    // get records
    // operate on record(s)
    match &cli.command {
        Commands::Search { term } => {
            for record in db.records().iter().filter(|&e| e.search(Some(term))) {
                println!("{}", record.to_csv())
            }
        }
        Commands::Password { term, print } => {
            let recs = db.records();

            // look for an exact "group.title" match first
            // then look for any entries containing our term
            if let Some(exact) = recs.iter().find(|&e| e.matchp(Some(term))) {
                if *print {
                    println!("{}", exact.password().unwrap());
                } else {
                    password_to_clipboard(exact.password().unwrap().to_string());
                }
            } else {
                let matches: Vec<&PwsafeRecord> =
                    recs.iter().filter(|&e| e.search(Some(term))).collect();

                if matches.is_empty() {
                    eprintln!("No matches found.");
                } else if matches.len() > 1 {
                    eprintln!("Multiple matches: ");
                    for record in matches {
                        println!("{}", record.to_csv())
                    }
                } else if *print {
                    println!("{}", matches[0].password().unwrap());
                } else {
                    password_to_clipboard(matches[0].password().unwrap().to_string());
                }
            }
        }
        Commands::Show { term } => {
            println!("Showing entries matching: {}", term);
        }
    }
}
