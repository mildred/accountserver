import options
import strutils, strformat
import asyncdispatch, net
import asynchttpserver
import zfblast/server
import tables
import nativesockets
import json
import parseopt
import ./utils/parse_port
import ./utils/lineproto
import ./db/dbcommon
import ./db/migrations
import ./db/users
import ./db/domains
import ./db/op
import ./admin_routes
import ./session
import ./common
import ./api

const version {.strdefine.}: string = "(no version information)"

const doc = ("""
AccountServer provides HTTP server to manage accounts

Usage: accountserver [options]

Options:
  -h, --help                Print help
  --version                 Print version
  -d, --db <file>           Database file [default: accounts.db]
  --sockapi-port <port>     Socket API port [default: 7999]
  --sockapi-addr <addr>     Socket API bind address [default: 127.0.0.1]
  -p, --api-port <port>     API port [default: 8000]
  -a, --api-addr <addr>     API bind address [default: 127.0.0.1]
  -P, --admin-port <port>   Admin interface port [default: 8080]
  -A, --admin-addr <addr>   Admin interface bind address [default: 127.0.0.1]
  -v, --verbose             Be verbose
  --insecure-logs           Log with user param values (passwords included)
  --allow-replicate <token> Allow incoming replication with the given token
  --replicate-to <url>      Replicate operations to the given instance
  --jwt-secret <secret>     Set JWT secret

Note: systemd socket activation is not supported yet
""") & (when not defined(version): "" else: &"""

Version: {version}
""")

const CRLF = "\c\L"

const shortNoVal = {'v'}
const longNoVal = @["help", "version", "verbose", "insecure-logs"]
var opts = initOptParser(@[], shortNoVal = shortNoVal, longNoVal = longNoVal, allowWhitespaceAfterColon = false)

var
  arg_db: string
  arg_sockapi_port: string = "7999"
  arg_sockapi_addr = "127.0.0.1"
  arg_api_port: string = "8000"
  arg_api_addr: string = "127.0.0.1"
  arg_admin_port: string = "8000"
  arg_admin_addr: string = "127.0.0.1"
  arg_verbose: bool = false
  arg_insecure_logs: bool = false
  arg_allow_replicate: string = ""
  arg_replicate_to: string = ""
  arg_jwt_secret: string = ""

for kind, key, val in opts.getopt():
  case kind
  of cmdArgument:
    echo "Unknown argument " & key
    quit(1)
  of cmdLongOption, cmdShortOption:
    case key
    of "db", "d":         arg_db = val
    of "sockapi-port":    arg_sockapi_port = val
    of "sockapi-addr":    arg_sockapi_addr = val
    of "api-port", "p":   arg_api_port = val
    of "api-addr", "a":   arg_api_addr = val
    of "admin-port", "P": arg_admin_port = val
    of "admin-addr", "A": arg_admin_addr = val
    of "verbose", "v":    arg_verbose = true
    of "insecure-logs":   arg_insecure_logs = true
    of "allow-replicate": arg_allow_replicate = val
    of "replicate-to":    arg_replicate_to = val
    of "jwt-secret":      arg_jwt_secret = val
    of "help", "h":
      echo doc
      quit()
    of "version":
      echo version
      when defined(version):
        quit(0)
      else:
        quit(1)
    else:
      echo "Unknown argument: " & key & " " & val
      quit(1)
  of cmdEnd: assert(false) # cannot happen

proc main =
  echo &"Starting up accountserver version {version}..."
  echo &"Opening database {arg_db}"
  var db: DbConn = connect(arg_db)
  defer: db.close()

  if not migrate(db):
    echo "Invalid database"
    quit(1)

  let
    sessions = newSessionList(defaultSessionTimeout)
    arg_log = arg_verbose
    arg_ilog = arg_insecure_logs
    common = Common(
      sessions: sessions,
      db: db,
      replicate_token: arg_allow_replicate,
      replicate_to: if arg_replicate_to != "": split(arg_replicate_to, ' ') else: @[],
      jwt_secret: arg_jwt_secret)
    sockapi_port = parse_port(arg_sockapi_port, 7999)
    sockapi_addr = arg_sockapi_addr

  var
    admin_servers :seq[ZFBlast] = @[]
    api_servers :seq[AsyncHttpServer] = @[]

  for addr in (arg_admin_addr).split(","):
    admin_servers.add(newZFBlast(
      trace = arg_log,
      port = parse_port(arg_admin_port, def = 8080),
      address = addr))

  for addr in (arg_api_addr).split(","):
    let server = newAsyncHttpServer()
    let port = parse_port(arg_api_port, def = 8000)
    let ai_list = getAddrInfo(addr, port, AF_UNSPEC)
    defer: freeAddrInfo(ai_list)

    var ai = ai_list
    while ai != nil:
      let addr_str = ai.ai_addr.getAddrString
      let domain = ai.ai_family.toKnownDomain
      if domain.is_some:
        echo &"Listening API on {addr_str} port {port}"
        server.listen(port, addr_str, domain.get)
        api_servers.add(server)
      ai = ai.ai_next

  asyncCheck common.dbw.insert_all_data(db.extract_all(), only_replicate = true)

  var sockapi: AsyncSocket
  sockapi = newAsyncSocket()
  sockapi.setSockOpt(OptReuseAddr, true)
  sockapi.bindAddr(sockapi_port, sockapi_addr)
  sockapi.listen()

  echo &"Listening Socket API on {sockapi_addr} port {sockapi_port}"
  for admin_server in admin_servers:
    echo &"Listening admin on {admin_server.address} port {admin_server.port}"


  proc handle_simple_api_request(request: string): tuple[body: string, httpCode: HttpCode] {.gcsafe.} =
    result = handle_api_request(db, request, "", arg_log, arg_ilog)

  proc handle_http_api_request(query, body: string): tuple[body: string, httpCode: HttpCode] {.gcsafe.} =
    result = handle_api_request(db, query, body, arg_log, arg_ilog)

  proc sockapi_handle_client(client: AsyncSocket) {.async gcsafe.} =
    defer:
      client.close()
    while true:
      let rawline = await client.recv_line_end()
      if rawline == "":
        return
      var line = rawline
      stripLineEnd(line)
      let res = handle_simple_api_request(line)
      if line == rawline:
        await client.send(res.body)
        return
      else:
        await client.send(res.body & CRLF)

  proc sockapi_handle(sockapi: AsyncSocket) {.async gcsafe.} =
    while true:
      let client = await sockapi.accept()
      try:
        asyncCheck sockapi_handle_client(client)
      except:
        echo "----------"
        let e = getCurrentException()
        echo &"{e.name}: {e.msg}"
        #echo getStackTrace(e)
        echo "----------"

  proc admin_handler(ctx: HttpContext) {.async gcsafe.} =
    try:
      await admin_routes.handler(ctx, common)
    except:
      echo getCurrentExceptionMsg()

  proc do_serve(server: AsyncHttpServer, callback: proc (request: asynchttpserver.Request): Future[void] {.closure, gcsafe.}) {.async gcsafe.} =
    while true:
      try:
        await server.acceptRequest(callback)
      except:
        echo "----------"
        let e = getCurrentException()
        echo &"{e.name}: {e.msg}"
        #echo getStackTrace(e)
        echo "----------"

  proc api_handler(req: asynchttpserver.Request) {.async gcsafe.} =
    try:
      if req.url.path == "/domains.json":
        let domains = db.fetch_domains()
        await req.respond(Http200, $(%{
          "domains": %domains
        }))
      elif req.url.path == "/credentials.json":
        let credentials = db.fetch_credentials()
        await req.respond(Http200, $(%{
          "credentials": %credentials
        }))
      else:
        let res = handle_http_api_request(req.url.query, req.body)
        await req.respond(res.httpCode, res.body)

    except:
      await req.respond(Http500, "Internal Server Error")
      echo getCurrentExceptionMsg()

  for api_server in api_servers:
    asyncCheck api_server.doServe(api_handler)
  for admin_server in admin_servers:
    asyncCheck admin_server.doServe(admin_handler)
  asyncCheck sockapi_handle(sockapi)

  runForever()

main()

