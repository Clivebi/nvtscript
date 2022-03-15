if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803073" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2012-4932" );
	script_bugtraq_id( 56882 );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-12-11 13:59:06 +0530 (Tue, 11 Dec 2012)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Simple Invoices Multiple Cross Site Scripting Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8877 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/80625" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2012/Dec/73" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/118737/simpleinvoices-xss.txt" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to insert arbitrary
  HTML and script code, which will be executed in a user's browser session in the
  context of an affected site when the malicious data is being viewed." );
	script_tag( name: "affected", value: "Simple Invoices version 2011.1 and prior" );
	script_tag( name: "insight", value: "Input passed via the 'having' parameter to index.php
  (when 'module' and 'view' are set to different actions) is not properly
  sanitised before it is returned to the user." );
	script_tag( name: "solution", value: "Upgrade to Simple Invoices version 2012-1 or later." );
	script_tag( name: "summary", value: "This host is running Simple Invoices and is prone to multiple
  cross site scripting vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
	script_xref( name: "URL", value: "http://www.simpleinvoices.org/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
siPort = http_get_port( default: 8877 );
if(!http_can_host_php( port: siPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/simpleinvoices", "/invoice", "/", http_cgi_dirs( port: siPort ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( item: url, port: siPort );
	if(isnull( res )){
		continue;
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, ">Simple Invoices" ) && ContainsString( res, ">Dashboard" ) && ContainsString( res, ">Settings" )){
		url = url + "?module=invoices&view=manage&having=" + "<script>alert(document.cookie)</script>";
		if(http_vuln_check( port: siPort, url: url, check_header: TRUE, pattern: "<script>alert\\(document\\.cookie\\)</script>", extra_check: make_list( ">Simple Invoices",
			 ">Dashboard" ) )){
			security_message( port: siPort );
			exit( 0 );
		}
	}
}
exit( 99 );

