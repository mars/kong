return {
fields = {
    scope = {required = true, type = "string"},
    ldap_host = {required = true, type = "string"},
    ldap_port = {required = true, type = "number"},
    use_tls = {required = true, type = "boolean"},
    timeout = {required = true, type = "number", default = 10000},
  }
}