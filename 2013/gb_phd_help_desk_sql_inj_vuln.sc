if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803802" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_bugtraq_id( 60273 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-04 15:34:49 +0530 (Tue, 04 Jun 2013)" );
	script_name( "PHD Help Desk SQL Injection vulnerability" );
	script_xref( name: "URL", value: "http://1337day.com/exploit/20843" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/25915" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121869/phdhelpdesk-sql.txt" );
	script_xref( name: "URL", value: "http://forelsec.blogspot.in/2013/06/phd-help-desk-212-sqli-and-xss.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute
  arbitrary SQL commands or execute arbitrary HTML or web script in a user's
  browser session in context of an affected site." );
	script_tag( name: "affected", value: "PHD Help Desk version 2.12, other versions may also be affected" );
	script_tag( name: "insight", value: "The application does not validate the 'operador', 'contrasenia',
  and 'captcha' parameters upon submission to the login.php script." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is installed with PHD Help Desk and is prone to SQL
  injection vulnerability." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
host = http_host_name( port: port );
for dir in nasl_make_list_unique( "/", "/phd", "/helpdesk", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/login.php" ), port: port );
	if(rcvRes && ContainsString( rcvRes, ">PHD Help Desk" ) && ContainsString( rcvRes, "request access<" )){
		postdata = "operador='&captcha=&contrasenia=pass&submit=Enter";
		req = NASLString( "POST ", dir, "/login.php HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: ", strlen( postdata ), "\\r\\n", "\\r\\n", postdata );
		res = http_keepalive_send_recv( port: port, data: req );
		if(res && ( ContainsString( res, "You have an error in your SQL syntax;" ) ) && ( IsMatchRegexp( res, "<b>Notice</b>:.*login.php" ) )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

