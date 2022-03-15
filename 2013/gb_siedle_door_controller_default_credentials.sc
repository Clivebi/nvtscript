if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103820" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Siedle Door Controller Default Password" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-10-24 10:01:48 +0100 (Thu, 24 Oct 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Z-World_Rabbit/banner" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "impact", value: "The 'Service' account has a default password of 'Siedle' which gives almost
  full access to the system like adding, renaming, or deleting doors and users, and force all the doors open." );
	script_tag( name: "vuldetect", value: "This check tries to login into the remote Siedle Door Controller." );
	script_tag( name: "insight", value: "It was possible to login with username 'Service' and password 'Siedle'." );
	script_tag( name: "solution", value: "Change the password or contact your vendor for an update." );
	script_tag( name: "summary", value: "The remote Siedle Door Controller is prone to a default account
  authentication bypass vulnerability" );
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
if(!ContainsString( banner, "Server: Z-World Rabbit" )){
	exit( 0 );
}
url = "/login.zht";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "Siedle" )){
	exit( 0 );
}
host = http_host_name( port: port );
req = "POST /login.cgi HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Referer: http://" + host + "/login.zht\r\n" + "Content-Type: application/x-www-form-urlencoded\r\n" + "Content-Length: 125\r\n" + "\r\n" + "m_webdata.m_cgiLogin.m_user=Service&m_webdata.m_cgiLogin.m_passwd=Siedle&m_webdata.m_cgiLogin.m_lang=en&action.x=0&action.y=0";
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(!ContainsString( buf, "Set-Cookie" )){
	exit( 0 );
}
cookie = eregmatch( pattern: "Set-Cookie: ([^\r\n]+)", string: buf );
if(isnull( cookie[1] )){
	exit( 0 );
}
co = cookie[1];
req = "GET /cfg/usrlist.zht HTTP/1.1\r\n" + "Host: " + host + "\r\n" + "Cookie: " + co + "\r\n\r\n";
buf = http_send_recv( port: port, data: req, bodyonly: FALSE );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "usrlist.name" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

