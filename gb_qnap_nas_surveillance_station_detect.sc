if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145423" );
	script_version( "2021-02-22T04:16:37+0000" );
	script_tag( name: "last_modification", value: "2021-02-22 04:16:37 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-02-22 03:23:10 +0000 (Mon, 22 Feb 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "QNAP QTS Surveillance Station Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of QNAP QTS Surveillance Station." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_qnap_nas_detect.sc" );
	script_mandatory_keys( "qnap/qts", "qnap/port" );
	script_xref( name: "URL", value: "https://www.qnap.com/en/software/surveillance-station" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
if(!port = get_kb_item( "qnap/port" )){
	exit( 0 );
}
res = http_get_cache( port: port, item: "/cgi-bin/surveillance/index.html" );
if("<title>Surveillance Station</title>" && ContainsString( res, "NVR_SURVEILLANCE_STATION" )){
	version = "unknown";
	vers = eregmatch( pattern: "\\.(ico|jpg|png|js)\\?([0-9.]+)", string: res );
	if(!isnull( vers[2] )){
		version = split( buffer: vers[2], sep: ".", keep: FALSE );
		if(max_index( version ) == 4){
			version = version[0] + "." + version[1] + "." + version[2];
		}
	}
	set_kb_item( name: "qnap/surveillance/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:qnap:surveillance_station:" );
	if(!cpe){
		cpe = "cpe:/a:qnap:surveillance_station";
	}
	register_product( cpe: cpe, location: "/cgi-bin/surveillance", port: port, service: "www" );
	log_message( data: build_detection_report( app: "QNAP QTS Surveillance Station", version: version, install: "/cgi-bin/surveillance", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

