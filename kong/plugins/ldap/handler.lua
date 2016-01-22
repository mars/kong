local BasePlugin = require "kong.plugins.base_plugin"
local access = require "kong.plugins.ldap.access"

local LDAPHandler = BasePlugin.extend()

function LDAPHandler:new()
  return LDAPHandler.super.new("ldap")
end

function LDAPHandler:access(conf)
  LDAPHandler.super.access(self)
  access.execute(conf)
end
