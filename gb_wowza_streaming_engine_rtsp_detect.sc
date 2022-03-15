if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106224" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2016-09-07 11:27:17 +0700 (Wed, 07 Sep 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Wowza Streaming Engine Detection (RTSP)" );
	script_tag( name: "summary", value: "Detection of Wowza Streaming Engine

  The script attempts to identify Wowza Streaming Engine via RTSP banner to extract the version number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "rtsp_detect.sc" );
	script_require_ports( "Services/rtsp", 554 );
	script_mandatory_keys( "RTSP/server_banner/available" );
	script_xref( name: "URL", value: "https://www.wowza.com/products/streaming-engine" );
	exit( 0 );
}
require("host_details.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 554, proto: "rtsp" );
if(!banner = get_kb_item( "RTSP/" + port + "/server_banner" )){
	exit( 0 );
}
if(IsMatchRegexp( banner, "Server: *Wowza Streaming Engine" )){
	set_kb_item( name: "wowza_streaming_engine/detected", value: TRUE );
	set_kb_item( name: "wowza_streaming_engine/rtsp/detected", value: TRUE );
	set_kb_item( name: "wowza_streaming_engine/rtsp/port", value: port );
	version = "unknown";
	build = "unknown";
	ver = eregmatch( pattern: "Wowza Streaming Engine ([0-9.]+)", string: banner );
	if(!isnull( ver[1] )){
		version = ver[1];
		set_kb_item( name: "wowza_streaming_engine/rtsp/" + port + "/version", value: version );
		set_kb_item( name: "wowza_streaming_engine/rtsp/" + port + "/concluded", value: ver[0] );
	}
}
exit( 0 );

