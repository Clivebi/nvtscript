if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100164" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-04-24 20:04:08 +0200 (Fri, 24 Apr 2009)" );
	script_bugtraq_id( 34551 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Phorum Multiple Cross Site Scripting Vulnerabilities" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "phorum_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phorum/detected" );
	script_tag( name: "summary", value: "According to its version number, the remote version of Phorum is
  prone to multiple cross-site scripting vulnerabilities because the
  application fails to sufficiently sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker can exploit these issues to steal cookie-based
  authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "Phorum 5.2.10 and 5.2-dev are vulnerable, other versions may also be
  affected." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/34551" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore.
  General solution options are to upgrade to a newer release, disable respective features,
  remove the product or replace the product by another one." );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/phorum" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
vers = matches[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(version_is_equal( version: vers, test_version: "5.2.10" ) || ereg( pattern: "^5\\.2-dev$", string: vers )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 0 );

