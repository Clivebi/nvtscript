if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103921" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Areca Raid Storage Manager Default Admin Credentials" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-03-13 12:02:06 +0200 (Thu, 13 Mar 2014)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "Raid_Console/banner" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote Areca Raid Storage Manager web interface is prone to a default
  account authentication bypass vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with default credentials." );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "401 Unauthorized" ) || !ContainsString( banner, "WWW-Authenticate: Digest realm=\"Raid Console\"" ) || !ContainsString( banner, "nonce" )){
	exit( 0 );
}
nonce = eregmatch( pattern: "nonce=\"([^\"]+)", string: banner );
if(isnull( nonce[1] )){
	exit( 0 );
}
nonce = nonce[1];
cnonce = rand();
qop = "auth";
nc = "00000001";
ha1 = hexstr( MD5( "admin:Raid Console:0000" ) );
ha2 = hexstr( MD5( "GET:/" ) );
response = hexstr( MD5( NASLString( ha1, ":", nonce, ":", nc, ":", cnonce, ":", qop, ":", ha2 ) ) );
host = http_host_name( port: port );
req = "GET / HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Authorization: Digest username=\"admin\", realm=\"Raid Console\"," + "nonce=\"" + nonce + "\", uri=\"/\"," + "response=\"" + response + "\", qop=" + qop + ", nc=" + nc + "," + "cnonce=\"" + cnonce + "\"\r\n" + "\r\n";
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "<title>Raid Storage Manager</title>" )){
	report = "It was possible to login using \"admin\" as username and \"0000\" as password.\n";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

