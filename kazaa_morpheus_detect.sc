if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10751" );
	script_version( "2021-03-22T07:55:33+0000" );
	script_tag( name: "last_modification", value: "2021-03-22 07:55:33 +0000 (Mon, 22 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Kazaa / Morpheus Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2005 SecuriTeam" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 1214 );
	script_mandatory_keys( "X-Kazaa-Username/banner" );
	script_tag( name: "summary", value: "HTTP based detection of the Kazaa / Morpheus server." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 1214 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "X-Kazaa-Username: " )){
	buf = strstr( banner, "X-Kazaa-Username: " );
	buf = buf - "X-Kazaa-Username: ";
	subbuf = strstr( buf, NASLString( "\\r\\n" ) );
	buf = buf - subbuf;
	username = buf;
	if(!username){
		exit( 0 );
	}
	buf = "Remote host reported that the username used is: ";
	buf = buf + username;
	set_kb_item( name: "kazaa/username", value: username );
	log_message( data: buf, port: port );
}
exit( 0 );

