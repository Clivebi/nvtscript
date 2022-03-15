if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19584" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_bugtraq_id( 14726 );
	script_cve_id( "CVE-2005-2836" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "Phorum register.php Cross-Site Scripting" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 David Maciejak" );
	script_family( "Web application abuses" );
	script_dependencies( "phorum_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "phorum/detected" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/fulldisclosure/2005-09/0018.html" );
	script_tag( name: "solution", value: "Upgrade to Phorum 5.0.18 or later." );
	script_tag( name: "summary", value: "The remote version of Phorum contains a script called 'register.php'
  which is vulnerable to a cross-site scripting attack." );
	script_tag( name: "impact", value: "An attacker may exploit this problem to steal the authentication credentials of third
  party users." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
install = get_kb_item( NASLString( "www/", port, "/phorum" ) );
if(isnull( install )){
	exit( 0 );
}
matches = eregmatch( string: install, pattern: "^(.+) under (/.*)$" );
if(!isnull( matches )){
	ver = matches[1];
	if(IsMatchRegexp( ver, "^([0-4]\\..*|5\\.0\\.([0-9][^0-9]*|1[0-7][^0-9]*))$" )){
		security_message( port );
	}
}

