if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10920" );
	script_version( "2021-03-18T13:55:00+0000" );
	script_tag( name: "last_modification", value: "2021-03-18 13:55:00 +0000 (Thu, 18 Mar 2021)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "RemotelyAnywhere Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_family( "Service detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 2000 );
	script_mandatory_keys( "RemotelyAnywhere/banner" );
	script_tag( name: "summary", value: "HTTP based detection of RemotelyAnywhere." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 2000 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "RemotelyAnywhere" )){
	exit( 0 );
}
if(egrep( pattern: "^Server\\s*:\\s*RemotelyAnywhere", string: banner, icase: TRUE )){
	log_message( port: port );
}
exit( 0 );

