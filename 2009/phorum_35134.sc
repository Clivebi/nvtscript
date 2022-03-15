if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100214" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-06-01 13:46:24 +0200 (Mon, 01 Jun 2009)" );
	script_bugtraq_id( 35134 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Phorum 'image/bmp' MIME Type HTML Injection Vulnerability" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "phorum_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phorum/detected" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "According to its version number, the remote version of Phorum is
  prone to an HTML-injection vulnerability because the application
  fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "Attacker-supplied HTML and script code would execute in the context
  of the affected site, potentially allowing the attacker to steal
  cookie-based authentication credentials or to control how the site
  is rendered to the user, other attacks are also possible." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/35134" );
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
	if(version_is_less( version: vers, test_version: "5.2.11" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "5.2.11" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

