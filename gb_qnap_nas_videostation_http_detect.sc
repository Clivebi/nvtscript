if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146084" );
	script_version( "2021-06-07T05:07:13+0000" );
	script_tag( name: "last_modification", value: "2021-06-07 05:07:13 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-07 04:34:23 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "QNAP QTS Video Station Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of QNAP QTS Video Station." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
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
res = http_get_cache( port: port, item: "/video/" );
if(ContainsString( res, "<title>Video Station</title>" ) && ContainsString( res, "__REACT_DEVTOOLS_GLOBAL_HOOK__" )){
	version = "unknown";
	url = "/video/api/user.php";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "<appVersion>([0-9.]+)<", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	set_kb_item( name: "qnap/videostation/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:qnap:video_station:" );
	if(!cpe){
		cpe = "cpe:/a:qnap:video_station";
	}
	register_product( cpe: cpe, location: "/video", port: port, service: "www" );
	log_message( data: build_detection_report( app: "QNAP QTS Video Station", version: version, cpe: cpe, install: "/video", concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

