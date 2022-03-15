if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113661" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-03-30 14:14:14 +0100 (Mon, 30 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Wowza Streaming Engine Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "wowza_streaming_engine/banner" );
	script_tag( name: "summary", value: "Checks whether Wowza Streaming Engine is present on
  the target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://www.wowza.com/products/streaming-engine" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_remote_headers( port: port );
if(IsMatchRegexp( buf, "Server: *WowzaStreamingEngine" )){
	set_kb_item( name: "wowza_streaming_engine/detected", value: TRUE );
	set_kb_item( name: "wowza_streaming_engine/http/detected", value: TRUE );
	set_kb_item( name: "wowza_streaming_engine/http/port", value: port );
	version = "unknown";
	ver = eregmatch( string: buf, pattern: "WowzaStreamingEngine/([0-9.]+)" );
	if(!isnull( ver[1] )){
		version = ver[1];
		set_kb_item( name: "wowza_streaming_engine/http/" + port + "/version", value: version );
		set_kb_item( name: "wowza_streaming_engine/http/" + port + "/concluded", value: ver[0] );
	}
}
exit( 0 );

