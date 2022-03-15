if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105023" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CS121 UPS Default Admin Credentials" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-05-12 11:02:06 +0200 (Mon, 12 May 2014)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "HyNetOS/banner" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote CS121 UPS web interface is prone to a default
  account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_app" );
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
if(!ContainsString( banner, "HyNetOS" )){
	exit( 0 );
}
buf = http_get_cache( item: "/", port: port );
if(!ContainsString( buf, "<title>CS121" )){
	exit( 0 );
}
req = http_get( item: "/admin/net.shtml", port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "401 Unauthorized" )){
	exit( 0 );
}
userpass = base64( str: "admin:cs121-snmp" );
useragent = http_get_user_agent();
req = "GET /admin/net.shtml HTTP/1.0\r\n" + "User-Agent: " + useragent + "\r\n" + "Authorization: Basic " + userpass + "\r\n\r\n";
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "Security Settings" ) && ContainsString( buf, "Gateway Address" )){
	report = "It was possible to login using \"admin\" as username and \"cs121-snmp\" as password.\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

