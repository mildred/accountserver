import options
import strutils, strformat
import asyncdispatch, net
import asynchttpserver
import zfblast/server
import tables
import nativesockets
import json
import base64
import parseopt
import ./utils/parse_port
import ./utils/lineproto
import ./db/dbcommon
import ./db/migrations
import ./db/users
import ./db/domains
import ./db/op
import ./httputil
import ./admin_routes
import ./session
import ./common

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

  proc get_param64(params: Table[string, seq[string]], key: string, def: string = ""): string =
    var val = params.get_params(key)
    if val.len > 0:
      return val[0]

    val = params.get_params(&"{key}64")
    if val.len > 0:
      return base64.decode(val[0].replace(" ", "+"))

    return def

  proc decode_data_raw(data: string): Table[string, seq[string]] {.gcsafe.} =
    iterator decodeDataRaw(data: string): tuple[key, value: string] =
      proc handleHexChar(c: char, x: var int, f: var bool) {.inline.} =
        case c
        of '0'..'9': x = (x shl 4) or (ord(c) - ord('0'))
        of 'a'..'f': x = (x shl 4) or (ord(c) - ord('a') + 10)
        of 'A'..'F': x = (x shl 4) or (ord(c) - ord('A') + 10)
        else: f = true
      proc decodePercent(s: string, i: var int): char =
        ## Converts `%xx` hexadecimal to the charracter with ordinal number `xx`.
        ##
        ## If `xx` is not a valid hexadecimal value, it is left intact: only the
        ## leading `%` is returned as-is, and `xx` characters will be processed in the
        ## next step (e.g. in `uri.decodeUrl`) as regular characters.
        result = '%'
        if i+2 < s.len:
          var x = 0
          var failed = false
          handleHexChar(s[i+1], x, failed)
          handleHexChar(s[i+2], x, failed)
          if not failed:
            result = chr(x)
            inc(i, 2)
      ## Reads and decodes CGI data and yields the (name, value) pairs the
      ## data consists of.
      proc parseData(data: string, i: int, field: var string, sep: char): int =
        result = i
        while result < data.len:
          let c = data[result]
          case c
          of '%': add(field, decodePercent(data, result))
          of '+': add(field, ' ')
          of '&': break
          else:
            if c == sep: break
            add(field, data[result])
          inc(result)

      var i = 0
      var name = ""
      var value = ""
      # decode everything in one pass:
      while i < data.len:
        setLen(name, 0) # reuse memory
        i = parseData(data, i, name, '=')
        setLen(value, 0) # reuse memory
        if i < data.len and data[i] == '=':
          inc(i) # skip '='
          i = parseData(data, i, value, '&')
        yield (name.string, value.string)
        if i < data.len:
          inc(i)

    result = initTable[string,seq[string]]()
    for key, value in decodeDataRaw(data):
      result.mget_or_put(key, @[]).add(value)

  proc handle_api_request(request: string): tuple[body: string, httpCode: HttpCode] {.gcsafe.} =
    let params = request.decode_data_raw()
    let req = params.get_param("req")
    if req == "lookup":
      let userid = params.get_param("userid")
      let realm = params.get_param("realm")
      let raw_req_params = params.get_params("param")
      var req_params: seq[string]
      echo &"API: Lookup userid={userid} realm={realm} params={raw_req_params}"
      for param in raw_req_params:
        if param == "cmusaslsecretPLAIN":
          req_params.add("userPassword")
        else:
          req_params.add(param)
      let values = db.fetch_user_params(userid, realm, req_params)
      var res: seq[(string,string)] = @[]
      if values.is_none:
        res.add(("res", "none"))
        if arg_log and not arg_ilog: echo &"Respond with: res=none"
      else:
        res.add(("res", "ok"))
        if arg_log and not arg_ilog: echo &"Respond with: res=ok"
        for k, v in values.get:
          res.add( (&"param.{k}", v) )
        #for param in raw_req_params:
        #  if param == "cmusaslsecretPLAIN":
        #    res.add( ("param.cmusaslsecretPLAIN", values.get["userPassword"]) )
      result.httpCode = Http200
      result.body = res.encode_params
      if arg_ilog: echo &"API: Respond with: {result.body}"
    elif req == "store":
      let userid = params.get_param("userid")
      let realm = params.get_param("realm")
      echo &"API: Store userid={userid} realm={realm}"
      echo &"API: Respond error"
      result.httpCode = Http500
      result.body = {
        "res": "error",
      }.encode_params
    elif req == "checkdomain":
      result.httpCode = Http200
      let trueStr = params.get_param("true", "true")
      let falseStr = params.get_param("false", "false")
      let domain = params.get_param64("domain")
      if db.has_domain(domain):
        echo &"API: Check domain {domain}: {trueStr}"
        result.body = trueStr
      else:
        echo &"API: Check domain {domain}: {falseStr}"
        result.body = falseStr
    elif req == "checkauth":
      result.httpCode = Http200
      let trueStr = params.get_param("true", "true")
      let falseStr = params.get_param("false", "false")
      let user = params.get_param64("user")
      let user_email = user.parse_email()
      let pass = params.get_param64("pass")
      if arg_ilog: echo &"API: Check auth user=\"{user}\" pass=\"{pass}\""
      if user_email.is_none:
        echo &"API: Check auth user={user}: {falseStr} (failed to decode user)"
        result.body = falseStr
      elif db.check_user_password(user_email.get(), pass):
        echo &"API: Check auth user={user}: {trueStr}"
        result.body = trueStr
      else:
        echo &"API: Check auth user={user}: {falseStr}"
        result.body = falseStr
    elif req == "getalias":
      result.httpCode = Http200
      let failureStr = params.get_param("failure", "")
      let domain = params.get_param64("domain")
      let localpart = params.get_param64("localpart")
      let alias = db.get_alias_or_catchall(Email(local_part: localpart, domain: domain))
      if alias.len == 0:
        echo &"API: Get alias {localpart}@{domain}: failed \"{failureStr}\""
        result.body = failureStr
      else:
        for a in alias:
          if result.body.len > 0: result.body.add(",")
          result.body.add($a)
        echo &"API: Get alias {localpart}@{domain}: success \"{result.body}\""
    else:
      echo &"API: Unknown request {req}"
      result.httpCode = Http400
      result.body = {
        "res": "error",
      }.encode_params

  proc sockapi_handle_client(client: AsyncSocket) {.async gcsafe.} =
    defer:
      client.close()
    var sep = ""
    while true:
      let rawline = await client.recv_line_end()
      if rawline == "":
        return
      var line = rawline
      stripLineEnd(line)
      let res = handle_api_request(line)
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
        let res = handle_api_request(req.body)
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

