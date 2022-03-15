if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103384" );
	script_bugtraq_id( 51359 );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "w-CMS HTML Injection and Local File Include Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51359" );
	script_xref( name: "URL", value: "http://w-cms.info/" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-01-11 11:29:25 +0100 (Wed, 11 Jan 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "w-CMS is prone to multiple HTML-injection vulnerabilities and a local
file-include vulnerability." );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to execute arbitrary
HTML and script code in the context of the affected browser, steal
cookie-based authentication credentials, and execute arbitrary local
scripts in the context of the webserver process. Other attacks are
also possible." );
	script_tag( name: "affected", value: "w-CMS 2.0.1 is vulnerable other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/cms", "/w-cms", "/w_cms", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/?p=<script>alert(/xss-test/)</script>";
	if(http_vuln_check( port: port, url: url, pattern: "<script>alert\\(/xss-test/\\)</script>", check_header: TRUE, extra_check: "Powered by.*w-CMS" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

