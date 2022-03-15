if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103666" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Netgear GS110TP Default Password" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-02-20 12:01:48 +0100 (Wed, 20 Feb 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Web_Server/banner" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "summary", value: "The remote Netgear GS110TP has the default password 'password'." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Web Server" )){
	exit( 0 );
}
url = "/base/main_login.html";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "<TITLE>NetGear GS110TP</TITLE>" )){
	exit( 0 );
}
host = http_host_name( port: port );
req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "DNT: 1\\r\\n", "Referer: http://", host, "/base/main_login.html\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: 52\\r\\n", "\\r\\n", "pwd=password&login.x=0&login.y=0&err_flag=0&err_msg=" );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!IsMatchRegexp( result, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
cookie = eregmatch( pattern: NASLString( "Set-Cookie: ([^\\r\\n ]+)" ), string: result );
if(isnull( cookie[1] )){
	exit( 0 );
}
co = cookie[1];
url = "/base/system/management/sysInfo.html";
req = NASLString( "GET ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", co, "\\r\\n\\r\\n" );
result = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( result, "System Name" ) && ContainsString( result, "Serial Number" ) && ContainsString( result, "Base MAC Address" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

