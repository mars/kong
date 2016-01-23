local ldap = require "lualdap"
local cache = require "kong.tools.database_cache"
local stringy = require "stringy"
local responses = require "kong.tools.responses"
local constants = require "kong.constants"
local crypto = require "kong.plugins.basic-auth.crypto"

local AUTHORIZATION = "authorization"
local PROXY_AUTHORIZATION = "proxy-authorization"

local _M = {}


local function retrieve_credentials(request, header_name, conf)
  local username, password
  local authorization_header = request.get_headers()[header_name]

  if authorization_header then
    local iterator, iter_err = ngx.re.gmatch(authorization_header, "\\s*[Bb]asic\\s*(.+)")
    if not iterator then
      ngx.log(ngx.ERR, iter_err)
      return
    end

    local m, err = iterator()
    if err then
      ngx.log(ngx.ERR, err)
      return
    end

    if m and table.getn(m) > 0 then
      local decoded_basic = ngx.decode_base64(m[1])
      if decoded_basic then
        local basic_parts = stringy.split(decoded_basic, ":")
        username = basic_parts[1]
        password = basic_parts[2]
      end
    end
  end

  if conf.hide_credentials then
    request.clear_header(header_name)
  end

  return username, password
end


local function validate_credentials_from_cache(credential, given_password)
  local digest, err = crypto.encrypt({consumer_id = credential.username, password = given_password})
  if err then
    ngx.log(ngx.ERR, "[ldap]  "..err)
  end
  return credential.password == digest
end

local function validate_credentials_from_ldap(conf, given_username, given_password)
  local who = conf.attribute.."="..given_username
  local binding = ldap.open_simple {uri = "ldap://"..conf.ldap_host..conf.ldap_port, who = conf.attribute.."="..given_username..","..conf.base, password = given_password}
  if not binding == nil then
    cache.set(cache.ldap_credential_key(given_username), {usename = given_username, password = given_password}, conf.ttl)
    return true;
  end  
end

local function validate(given_username, given_password, conf)  
  if validate_credentials_from_cache(given_username, given_password, conf) or validate_credentials_from_ldap(credential, given_password) then
    return true
  end
end

function _M.execute(conf)

  -- If both headers are missing, return 401
  if not (ngx.req.get_headers()[AUTHORIZATION] or ngx.req.get_headers()[PROXY_AUTHORIZATION]) then
    ngx.header["WWW-Authenticate"] = "Basic realm=\""..constants.NAME.."\""
    return responses.send_HTTP_UNAUTHORIZED()
  end
end

return _M