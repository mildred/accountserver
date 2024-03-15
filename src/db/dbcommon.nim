import db_connector/db_sqlite

proc connect*(dbfile: string): DbConn =
  result = db_sqlite.open(dbfile, "", "", "")

type DbWriteHandle* = object
  db*: DbConn
  replicate_to*: seq[string]

export DbConn
export close

