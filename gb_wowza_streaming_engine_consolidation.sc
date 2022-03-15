if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113662" );
	script_version( "2020-03-31T11:38:16+0000" );
	script_tag( name: "last_modification", value: "2020-03-31 11:38:16 +0000 (Tue, 31 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-03-30 14:56:55 +0100 (Mon, 30 Mar 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Wowza Streaming Engine Detection (Consolidation)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_wowza_streaming_engine_http_detect.sc", "gb_wowza_streaming_engine_rtsp_detect.sc" );
	script_mandatory_keys( "wowza_streaming_engine/detected" );
	script_tag( name: "summary", value: "Checks whether Wowza Streaming Engine
  is present on the target system." );
	script_xref( name: "URL", value: "https://www.wowza.com/products/streaming-engine" );
	exit( 0 );
}
CPE = "cpe:/a:wowza:streaming_engine:";
require("host_details.inc.sc");
require("cpe.inc.sc");
version = "unknown";
concluded = "";
extra = "Concluded from the following protocols:";
for proto in make_list( "rtsp",
	 "http" ) {
	if(!ports = get_kb_list( "wowza_streaming_engine/" + proto + "/port" )){
		continue;
	}
	for port in ports {
		vers = get_kb_item( "wowza_streaming_engine/" + proto + "/" + port + "/version" );
		concl = get_kb_item( "wowza_streaming_engine/" + proto + "/" + port + "/concluded" );
		if(!isnull( vers ) && version == "unknown"){
			version = vers;
		}
		if( concluded == "" ) {
			concluded = toupper( proto );
		}
		else {
			if(!ContainsString( concluded, toupper( proto ) )){
				concluded += ", " + toupper( proto );
			}
		}
		if(!isnull( concl )){
			extra += "\n\n" + port + "/" + toupper( proto ) + ":";
			extra += "\n    " + concl;
		}
		if( proto == "http" ) {
			service = "www";
		}
		else {
			service = proto;
		}
		cpe = build_cpe( value: vers, exp: "([0-9.]+)", base: CPE );
		register_product( cpe: cpe, location: port + "/tcp", port: port, service: service );
	}
}
report = build_detection_report( app: "Wowza Streaming Engine", version: version, cpe: CPE, concluded: concluded, extra: extra );
log_message( port: 0, data: report );
exit( 0 );

