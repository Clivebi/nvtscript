if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805205" );
	script_version( "2021-03-11T10:58:32+0000" );
	script_cve_id( "CVE-2014-9215" );
	script_bugtraq_id( 71471 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-03-11 10:58:32 +0000 (Thu, 11 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-12-08 15:01:55 +0530 (Mon, 08 Dec 2014)" );
	script_name( "PBBoard CMS 'email' Parameter SQL Injection Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/35473" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/534149/30/0/threaded" );
	script_xref( name: "URL", value: "http://www.itas.vn/news/ITAS-Team-discovered-SQL-Injection-in-PBBoard-CMS-68.html" );
	script_tag( name: "summary", value: "PBBoard CMS is prone to an SQL injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET requests and checks
  the response." );
	script_tag( name: "insight", value: "Input passed via the 'email' POST parameter to
  the /includes/functions.class.php script is not properly sanitized before
  returning to users." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to inject or manipulate SQL queries in the back-end database allowing for the
  manipulation or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "PBBoard version 3.0.1 and prior." );
	script_tag( name: "solution", value: "Update to latest PBBoard version 3.0.1
  (updated on 28/11/2014) or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
for dir in nasl_make_list_unique( "/", "/PBBoard", "/pbb", "/forum", "/cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/index.php", port: port );
	if(res && IsMatchRegexp( res, ">Powered by.*PBBoard<" )){
		url = dir + "/index.php?page=register&checkemail=1";
		postData = "email='Sql-Injection-Test@f.com";
		req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded; charset=UTF-8", "\\r\\n", "Referer: http://", host, dir, "/index.php?page=register&index=1&agree=1", "\\r\\n", "Content-Length: ", strlen( postData ), "\\r\\n\\r\\n", postData, "\\r\\n" );
		res = http_keepalive_send_recv( port: port, data: req );
		if(res && ContainsString( res, "You have an error in your SQL syntax" ) && ContainsString( res, "Sql-Injection-Test" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

