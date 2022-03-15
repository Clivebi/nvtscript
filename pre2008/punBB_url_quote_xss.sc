if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15941" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_xref( name: "OSVDB", value: "7973" );
	script_name( "PunBB URL Quote Tag XSS" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2004 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "punBB_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "punBB/installed" );
	script_xref( name: "URL", value: "http://www.punbb.org/changelogs/1.1.4_to_1.1.5.txt" );
	script_tag( name: "solution", value: "Upgrade to PunBB version 1.1.5 or later." );
	script_tag( name: "summary", value: "According to its banner, the remote version of PunBB is vulnerable to
  cross-site scripting flaws because the application does not validate URL and quote tags." );
	script_tag( name: "impact", value: "With a specially-crafted URL, an attacker may be able to inject arbitrary
  HTML and script code into a user's browser, resulting in a loss of integrity." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
install = get_kb_item( NASLString( "www/", port, "/punBB" ) );
if(isnull( install )){
	exit( 0 );
}
matches = eregmatch( string: install, pattern: "^(.+) under (/.*)$" );
if(!isnull( matches )){
	ver = matches[1];
	if(egrep( pattern: "^(0\\.|1\\.0|1\\.1[^.]|1\\.1\\.[0-4]([^0-9]|$))", string: ver )){
		security_message( port: port );
		exit( 0 );
	}
}
exit( 99 );

