if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141488" );
	script_version( "$Revision: 11446 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-18 11:05:56 +0200 (Tue, 18 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2018-09-18 14:33:10 +0700 (Tue, 18 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "QNAP QTS Music Station Detection" );
	script_tag( name: "summary", value: "Detection of QNAP QTS Music Station.

The script sends a connection request to the server and attempts to detect QNAP QTS Music Station and to extract
its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts", "qnap/port" );
	script_xref( name: "URL", value: "https://www.qnap.com" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_kb_item( "qnap/port" )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/musicstation/" );
if(ContainsString( res, "<title>Music Station</title>" ) && ContainsString( res, "QMS.Mime" )){
	version = "unknown";
	vers = eregmatch( pattern: "QMS.version = \"([0-9.]+) [^\"]+\"", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "qnap_musicstation/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:qnap:music_station:" );
	if(!cpe){
		cpe = "cpe:/a:qnap:music_station";
	}
	register_product( cpe: cpe, location: "/musicstation", port: port );
	log_message( data: build_detection_report( app: "QNAP QTS Music Station", version: version, install: "/musicstation", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

