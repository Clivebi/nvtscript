if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143103" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-11-07 09:52:07 +0000 (Thu, 07 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "LIVE555 Streaming Media Server Detection (HTTP)" );
	script_tag( name: "summary", value: "This script performs a HTTP based detection of LIVE555 Streaming Media Server." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner || !ContainsString( banner, "LIVE555 Streaming Media" )){
	exit( 0 );
}
set_kb_item( name: "live555/streaming_media/detected", value: TRUE );
set_kb_item( name: "live555/streaming_media/http/port", value: port );
version = "unknown";
vers = eregmatch( pattern: "LIVE555 Streaming Media v([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
	set_kb_item( name: "live555/streaming_media/http/" + port + "/concluded", value: vers[0] );
}
set_kb_item( name: "live555/streaming_media/http/" + port + "/version", value: version );
exit( 0 );

