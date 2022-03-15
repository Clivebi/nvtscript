if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100371" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-12-02 17:30:58 +0100 (Wed, 02 Dec 2009)" );
	script_bugtraq_id( 37182 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Simple Machines Forum Multiple Security Vulnerabilities" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/37182" );
	script_xref( name: "URL", value: "http://code.google.com/p/smf2-review/issues/list" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "gb_simple_machines_forum_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "SMF/installed" );
	script_tag( name: "solution", value: "Reportedly, the vendor fixed some of the issues in the release 1.1.11." );
	script_tag( name: "summary", value: "Simple Machines Forum is prone to multiple security vulnerabilities:

  - A remote PHP code-execution vulnerability

  - Multiple cross-site scripting vulnerabilities

  - Multiple cross-site request-forgery vulnerabilities

  - An information-disclosure vulnerability

  - Multiple denial-of-service vulnerabilities." );
	script_tag( name: "impact", value: "Attackers can exploit these issues to execute arbitrary script code
  within the context of the webserver, perform unauthorized actions on
  behalf of legitimate users, compromise the affected application,
  steal cookie-based authentication credentials, obtain information
  that could aid in further attacks or cause denial-of-service
  conditions." );
	script_tag( name: "affected", value: "These issues affect Simple Machines Forum 2.0 RC2. Some of these
  issues also affect version 1.1.10." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
port = http_get_port( default: 80 );
if(!version = get_kb_item( NASLString( "www/", port, "/SMF" ) )){
	exit( 0 );
}
if(!matches = eregmatch( string: version, pattern: "^(.+) under (/.*)$" )){
	exit( 0 );
}
vers = matches[1];
if(!isnull( vers ) && !ContainsString( "unknown", vers )){
	if(version_is_equal( version: vers, test_version: "1.1.10" ) || version_is_equal( version: vers, test_version: "2.0.RC2" )){
		security_message( port: port, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
exit( 99 );

