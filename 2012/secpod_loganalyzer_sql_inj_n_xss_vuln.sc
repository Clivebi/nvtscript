if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902840" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 53664 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-05-28 15:15:15 +0530 (Mon, 28 May 2012)" );
	script_name( "Adiscon LogAnalyzer Multiple SQL Injection and XSS Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/49223" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/113037/CSA-12005.txt" );
	script_xref( name: "URL", value: "http://www.codseq.it/advisories/multiple_vulnerabilities_in_loganalyzer" );
	script_xref( name: "URL", value: "http://loganalyzer.adiscon.com/news/loganalyzer-v3-4-3-v3-stable-released" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to steal cookie based
  authentication credentials, compromise the application, access or modify
  data or  exploit latent vulnerabilities in the underlying database." );
	script_tag( name: "affected", value: "Adiscon LogAnalyzer version 3.4.2 and prior" );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - Input passed via the 'filter' parameter to index.php, the 'id' parameter to
    admin/reports.php and admin/searches.php is not properly sanitised before
    being returned to the user.

  - Input passed via the 'Columns[]' parameter to admin/views.php is not
    properly sanitised before being used in SQL queries." );
	script_tag( name: "solution", value: "Upgrade to Adiscon LogAnalyzer version 3.4.3 or later." );
	script_tag( name: "summary", value: "This host is running Adiscon LogAnalyzer and is prone to multiple
  SQL injection and cross site scripting vulnerabilities." );
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
for dir in nasl_make_list_unique( "/loganalyzer", "/log", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: port );
	if(isnull( res )){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">Adiscon LogAnalyzer<" )){
		url += "?filter=</title><script>alert(document.cookie)</script>";
		if(http_vuln_check( port: port, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: ">Adiscon LogAnalyzer<" )){
			security_message( port: port );
			exit( 0 );
		}
	}
}
exit( 99 );

