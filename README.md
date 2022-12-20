A simple cli utility for accessing PWSafe3 databases

This is a `clap` based wrapper for the `pwsafer` crate for limited
access to PWSafe3 database records.  Its able to get passwords to your
clipboard or stdout, and to export a database to JSONL.


It was tested against pwsafe3 dbs produced by https://pwsafe.info/

# Usage

```
A simple CLI utility for accessing PWSafev3 databases

Usage: pwget [OPTIONS] <COMMAND>

Commands:
  list  List entries on stdout, in JSONL
  pass  Retrieve a password for an entry
  help  Print this message or the help of the given subcommand(s)

Options:
  -d, --dbfile <DBFILE>  The pwsafe3 database file to read. [env: PWSAFE_DB=] [default: pwsafe3.db]
  -h, --help             Print help information
  -V, --version          Print version information
```


To list your entries

```
pwget list
```

And you'll be presented with all the entries in the database, in JSONL:

```
{"uuid":"e6c9a7f4-a18c-4763-b71a-539c23222504","group":"","title":null,"username":null,"url":null,"email_address":null}
{"uuid":"0508d635-3bf5-782e-4733-c4666906c063","group":null,"title":"anexample","username":"craig@red-bean.com","url":"http://example.org","email_address":"craig@example.org"}
{"uuid":"10460aa1-8dfd-fd60-0432-82e3134e5346","group":"agroup","title":"another","username":null,"url":null,"email_address":null}
{"uuid":"ba100e3a-b4e8-a88a-6037-80285e37458d","group":"agroup","title":"duplicate","username":null,"url":null,"email_address":null}
{"uuid":"bfa5df0f-3db8-fa8f-4309-26240d753a71","group":"agroup","title":"duplicate","username":null,"url":null,"email_address":null}
```

If you want pretty output, use `jq`.

You can limit it to entries matching a `group.title` or `uuid` by providing a term:

```
pwget list dup
```

To copy a password to your clipboard:

```
pwget pass agroup.another
```

If you need to disambiguate duplicate titles, use the uuid:

```
pwget pass bfa5d
```
