if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103767" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-08-19 11:03:03 +0100 (Mon, 19 Aug 2013)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Avocent KVM Default Login" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "gb_default_credentials_options.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning", "default_credentials/disable_default_account_checks" );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain access to
  sensitive information or modify system configuration without requiring authentication." );
	script_tag( name: "vuldetect", value: "This check tries to login into the remote KVM as Admin." );
	script_tag( name: "insight", value: "It was possible to login with username 'Admin' and an empty password." );
	script_tag( name: "solution", value: "Set a password." );
	script_tag( name: "summary", value: "The remote Avocent KVM is prone to a default account
  authentication bypass vulnerability." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
buf = http_get_cache( port: port, item: "/login.php" );
if(!egrep( pattern: "<title>MPU[0-9A-Z]+ Explorer</title>", string: buf ) || !ContainsString( buf, "loginUsername" )){
	exit( 0 );
}
useragent = http_get_user_agent();
host = http_host_name( port: port );
req = "POST /login.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Accept-Encoding: Identity\r\n" + "DNT: 1\r\n" + "Connection: close\r\n" + "Referer: https://" + host + " /login.php\r\n" + "Cookie: avctSessionId=; /home.php-t1s=1\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: 59\r\n" + "\r\n" + "action=login&loginUsername=Admin&loginPassword=&language=de";
buf = http_keepalive_send_recv( port: port, data: req );
if(!ContainsString( buf, "302 Found" ) || !ContainsString( buf, "/home.php" )){
	exit( 0 );
}
session = eregmatch( pattern: "avctSessionId=([0-9]+)", string: buf );
if(isnull( session[1] )){
	exit( 0 );
}
avctSessionId = session[1];
req = "GET /home.php HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "User-Agent: " + useragent + "\r\n" + "Connection: close\r\n" + "Accept-Encoding: Identity\r\n" + "Accept-Language:en-us;\r\n" + "Cookie: avctSessionId=" + avctSessionId + "\r\n\r\n";
buf = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( buf, "Admin" ) && ContainsString( buf, "/appliance-overview.php" ) && ContainsString( buf, "/logout.php" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

