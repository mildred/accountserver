import jwt
import times
import json
import zfblast/server
import cookies
import options
import ../session
import ../httputil
import ../common
import ../views/layout_anon
import ../views/login
import ../db/users

proc admin_login*(ctx: HttpContext, com: CommonRequest) {.async gcsafe.} =
  if ctx.request.httpMethod == HttpPost:
    let params = ctx.request.body.read_file().decode_data()
    let email = parse_email(params.get_param("email"))
    let password = params.get_param("password")

    if email.is_some and com.db.check_user_password(email.get, password):
      let sess = com.sessions.createSession()
      sess.data.email = email.get
      ctx.response.httpCode = Http303
      ctx.response.headers.add("Location", &"{com.prefix}/")
      ctx.response.headers.add("Set-Cookie", cookies.setCookie("sid", sess.sid, noName = true))
      return

  ctx.response.body = com.layout_anon(
    title = "Log-In",
    main = com.login())

proc admin_login_jwt*(ctx: HttpContext, com: CommonRequest) {.async gcsafe.} =
  if ctx.request.httpMethod == HttpPost:
    let params = ctx.request.body.read_file().decode_data()
    let email0 = params.get_param("email")
    let email = parse_email(email0)
    let password = params.get_param("password")

    if email.is_some and com.db.check_user_password(email.get, password):
      let e: string = $email.get
      var token = toJWT(%*{
        "header": {
          "typ": "JWT",
          "alg": "HS256"
        },
        "claims": {
          "email": e,
          "exp": (getTime() + 1.days).toUnix()
        }
      })
      token.sign(com.com.jwt_secret)

      ctx.response.httpCode = Http303
      ctx.response.headers.add("Location", "./")
      ctx.response.headers.add("Set-Cookie", cookies.setCookie("user_token", $token, noName = true))
      return

  ctx.response.body = com.layout_anon(
    title = "Log-In",
    main = com.login())

