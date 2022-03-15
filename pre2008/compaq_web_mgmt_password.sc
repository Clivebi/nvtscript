if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11879" );
	script_version( "2021-08-09T14:28:51+0000" );
	script_tag( name: "last_modification", value: "2021-08-09 14:28:51 +0000 (Mon, 09 Aug 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Compaq Web-based Management Login" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 SensePost" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 2381 );
	script_mandatory_keys( "CompaqHTTPServer/banner" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Checks the administrator account on Compaq Web-based Management / HP System Management
  agents for the default or predictable passwords." );
	script_tag( name: "solution", value: "Ensure that all passwords for Compaq Web-based Management / HP System Management Agent
  accounts are set to stronger, less easily guessable, alternatives. As a further precaution, use the 'IP Restricted Logins'
  setting to allow only authorised IP's to manage this agent." );
	script_tag( name: "insight", value: "The Compaq Web-based Management / HP System Management Agent active on the remote host
  is configured with the default, or a predictable, administrator password.

  Depending on the agents integrated, this allows an attacker to view sensitive and verbose system information, and may even
  allow more active attacks such as rebooting the remote system. Furthermore, if an SNMP agent is configured on the remote
  host it may disclose the SNMP community strings in use, allowing an attacker to set device configuration if the 'write'
  community string is uncovered.

  To manually test for this bug, you can log into the Compaq web server via a browser (https://example.com:2381/).
  Log in with a username/password combination of administrator/" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
passlist = make_list( "administrator",
	 "admin",
	 "cim",
	 "cim7",
	 "password" );
port = http_get_port( default: 8086, ignore_broken: TRUE );
req = http_get( item: "/cpqlogin.htm?RedirectUrl=/&RedirectQueryString=", port: port );
res = http_keepalive_send_recv( port: port, data: req );
if(!res){
	exit( 0 );
}
if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( res, "Server\\s*:\\s*CompaqHTTPServer/" ) && IsMatchRegexp( res, "Set-Cookie\\s*:\\s*Compaq" )){
	for pass in passlist {
		cookie = eregmatch( pattern: "Set-Cookie: (.*);", string: res );
		if(isnull( cookie[1] )){
			exit( 0 );
		}
		poststr = NASLString( "redirecturl=&redirectquerystring=&user=administrator&password=", pass );
		req = NASLString( "POST /proxy/ssllogin HTTP/1.0\\r\\n", "Cookie: " + cookie[1], "\\r\\n", "Content-Length: ", strlen( poststr ), "\\r\\n\\r\\n", poststr, "\\r\\n" );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "CpqElm-Login: success" )){
			report = "It was possible to login with the password'" + pass + "'.";
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

