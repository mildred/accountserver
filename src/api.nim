import options
import strutils, strformat
import net
import asynchttpserver
import zfblast/server
import tables
import nativesockets
import base64
import json
import ./db/dbcommon
import ./db/users
import ./db/domains
import ./httputil

proc get_param64(params: Table[string, seq[string]], key: string, def: string = ""): string =
  let param_name = params.get_param(&"{key}param", key)

  var val = params.get_params(param_name)
  if val.len > 0:
    return val[0]

  val = params.get_params(&"{param_name}64")
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
      yield (name, value)
      if i < data.len:
        inc(i)

  result = initTable[string,seq[string]]()
  for key, value in decodeDataRaw(data):
    result.mget_or_put(key, @[]).add(value)

proc `%`(data: open_array[(string,string)]): JsonNode =
  var res: seq[tuple[key: string, val: JsonNode]]
  for pair in data:
    res.add((pair[0], %pair[1]))
  result = %res

proc handle_api_request*(db: DbConn, request, reqbody: string, arg_log, arg_ilog: bool): tuple[body: string, httpCode: HttpCode] {.gcsafe.} =
  var params = request.decode_data_raw()
  var is_json = false

  try:
    for key, val in parse_json(reqbody).to(Table[string,string]):
      params.mget_or_put(key, @[]).add(val)
    is_json = true
  except JsonParsingError:
    for key, vals in reqbody.decode_data_raw():
      for val in vals:
        params.mget_or_put(key, @[]).add(val)

  proc encode_result(res: open_array[(string,string)]): string =
    if is_json:
      result = $(%*res)
    else:
      result = res.encode_params

  proc return_success(params: Table[string, seq[string]], res: var tuple[body: string, httpCode: HttpCode], success: bool) {.gcsafe.} =
    let resp = params.get_param("resp", "str")
    let trueStr = params.get_param("true", "true")
    let trueCode = params.get_param("true", "200").parseInt
    let falseStr = params.get_param("false", "false")
    let falseCode = params.get_param("false", "400").parseInt
    if resp == "str":
      res.body = if success: trueStr else: falseStr
    elif resp == "":
      res.httpCode = if success: HttpCode(trueCode) else: HttpCode(falseCode)
    else:
      res.httpCode = Http400
      res.body = {
        "res": "error",
        "error": "invalid_resp",
        "message": "resp was of unknown value (must be one of: str, status)",
      }.encode_result

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
    result.body = res.encode_result
    if arg_ilog: echo &"API: Respond with: {result.body}"
  elif req == "store":
    let userid = params.get_param("userid")
    let realm = params.get_param("realm")
    echo &"API: Store userid={userid} realm={realm}"
    echo &"API: Respond error"
    result.httpCode = Http500
    result.body = {
      "res": "error",
    }.encode_result
  elif req == "checkdomain":
    result.httpCode = Http200
    let domain = params.get_param64("domain")
    if db.has_domain(domain):
      echo &"API: Check domain {domain}: success"
      params.return_success(result, true)
    else:
      echo &"API: Check domain {domain}: failure"
      params.return_success(result, false)
  elif req == "checkauth":
    result.httpCode = Http200
    let user = params.get_param64("user")
    let user_email = user.parse_email()
    let pass = params.get_param64("pass")
    if arg_ilog: echo &"API: Check auth user=\"{user}\" pass=\"{pass}\""
    if user_email.is_none:
      echo &"API: Check auth user={user}: failure (failed to decode user)"
      result.body = {
        params.get_param("userparam", "user"): "",
      }.encode_result
      params.return_success(result, false)
    elif db.check_user_password(user_email.get(), pass):
      echo &"API: Check auth user={user}: success"
      result.body = {
        params.get_param("userparam", "user"): user,
      }.encode_result
      params.return_success(result, true)
    else:
      echo &"API: Check auth user={user}: failure"
      result.body = {
        params.get_param("userparam", "user"): "",
      }.encode_result
      params.return_success(result, false)
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
    }.encode_result

