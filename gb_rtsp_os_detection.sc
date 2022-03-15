if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108451" );
	script_version( "2021-05-20T09:32:28+0000" );
	script_tag( name: "last_modification", value: "2021-05-20 09:32:28 +0000 (Thu, 20 May 2021)" );
	script_tag( name: "creation_date", value: "2018-07-23 10:06:14 +0200 (Mon, 23 Jul 2018)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Operating System (OS) Detection (RTSP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "rtsp_detect.sc" );
	script_mandatory_keys( "RTSP/server_or_auth_banner/available" );
	script_tag( name: "summary", value: "RTSP server based Operating System (OS) detection." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
SCRIPT_DESC = "Operating System (OS) Detection (RTSP)";
BANNER_TYPE = "RTSP Server banner";
port = service_get_port( default: 554, proto: "rtsp" );
if(server_banner = get_kb_item( "RTSP/" + port + "/server_banner" )){
	if(ContainsString( server_banner, "IQinVision Embedded" )){
		os_register_and_report( os: "Linux/Unix (Embedded)", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: server_banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(!IsMatchRegexp( server_banner, "^Server\\s*:\\s*GStreamer RTSP server$" )){
		unknown_banner = server_banner;
	}
}
if(auth_banner = get_kb_item( "RTSP/" + port + "/auth_banner" )){
	auth_banner_lo = tolower( auth_banner );
	if(ContainsString( auth_banner_lo, "basic realm=\"dahuartsp\"" )){
		os_register_and_report( os: "Linux/Unix (Embedded)", cpe: "cpe:/o:linux:kernel", banner_type: BANNER_TYPE, port: port, banner: auth_banner, desc: SCRIPT_DESC, runs_key: "unixoide" );
		exit( 0 );
	}
	if(unknown_banner){
		unknown_banner += "\n";
	}
	unknown_banner += auth_banner;
}
if(unknown_banner){
	os_register_unknown_banner( banner: unknown_banner, banner_type_name: BANNER_TYPE, banner_type_short: "rtsp_banner", port: port );
}
exit( 0 );

