if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805131" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-1032" );
	script_bugtraq_id( 72279 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-01-28 13:22:01 +0530 (Wed, 28 Jan 2015)" );
	script_name( "Kiwix Server 'pattern' Parameter Cross-Site Scripting Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Kiwix
  and is prone to an XSS vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check whether it is able to read cookie or not." );
	script_tag( name: "insight", value: "Input passed via the 'pattern' parameter
  to '/search' is not properly sanitised before being returned to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary HTML and script code in a users browser session
  in the context of an affected site." );
	script_tag( name: "affected", value: "Kiwix version 0.9 and prior." );
	script_tag( name: "solution", value: "Apply the patch manually from the referenced vendor link." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://sourceforge.net/p/kiwix/bugs/763" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/130007" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/534502/100/0/threaded" );
	script_xref( name: "URL", value: "http://sourceforge.net/p/kiwix/kiwix/ci/d1af5f0375c6db24d4071acf4806735725fd206e" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
http_port = http_get_port( default: 8000 );
rcvRes = http_get_cache( item: "/", port: http_port );
if(ContainsString( rcvRes, ">Welcome to Kiwix Server<" )){
	url = "/search?content=sadas&pattern=<script>" + "alert(document.cookie)</script>";
	if(http_vuln_check( port: http_port, url: url, check_header: TRUE, pattern: "<script>alert\\(document.cookie\\)</script>", extra_check: ">Fulltext search unavailable<" )){
		report = http_report_vuln_url( port: http_port, url: url );
		security_message( port: http_port, data: report );
		exit( 0 );
	}
}
exit( 99 );

