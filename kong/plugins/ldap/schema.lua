return {
fields = {
    cache_credential = {required = true, type = "boolean"},
    ldap_host = {required = true, type = "string"},
    ldap_port = {required = true, type = "number"},
    use_tls = {required = true, type = "boolean"},
    cert = {required = true, type = "string"},
    key = {required = true, type = "string"},
    base_dn = {required = true, type = "string"},
    attribute = {required = true, type = "string"},
    timeout = {required = true, type = "number", default = 10000},
  }
}