if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103667" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Sharp MX-M850 Default Administrator Password" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-02-22 12:01:48 +0100 (Fri, 22 Feb 2013)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Rapid_Logic/banner" );
	script_xref( name: "URL", value: "http://sharp-world.com/" );
	script_tag( name: "solution", value: "Change the password." );
	script_tag( name: "summary", value: "The remote Sharp MX-M850 has the default password 'admin'." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: Rapid Logic/1.1" )){
	exit( 0 );
}
url = "/login.html";
req = http_get( item: url, port: port );
buf = http_send_recv( port: port, data: req );
if(!ContainsString( buf, "Set-Cookie" )){
	exit( 0 );
}
cookie = eregmatch( pattern: NASLString( "Set-Cookie: ([^\\r\\n ]+)" ), string: buf );
if(isnull( cookie[1] )){
	exit( 0 );
}
host = http_host_name( port: port );
req = NASLString( "POST /login.html?/main.html HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "DNT: 1\\r\\n", "Connection: close\\r\\n", "Referer: http://", host, "/login.html?/main.html\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Cookie: ", cookie[1], "\\r\\n", "Content-Length: 68\\r\\n", "\\r\\n", "ggt_textbox%2810006%29=admin&action=loginbtn&ggt_hidden%2810008%29=3" );
res = http_send_recv( port: port, data: req );
if(!ContainsString( res, "Set-Cookie" )){
	exit( 0 );
}
cookie = eregmatch( pattern: NASLString( "Set-Cookie: ([^\\r\\n ]+)" ), string: res );
if(isnull( cookie[1] )){
	exit( 0 );
}
req = NASLString( "GET /security_password.html HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Cookie: ", cookie[1], "\\r\\n\\r\\n" );
res = http_send_recv( port: port, data: req );
if(ContainsString( res, "User Name: Administrator" ) && ContainsString( res, "Logout(L)" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

