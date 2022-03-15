if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813817" );
	script_version( "2021-06-22T05:51:37+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-22 05:51:37 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-08-07 12:34:02 +0530 (Tue, 07 Aug 2018)" );
	script_name( "AVTech AVC 7xx DVR Device Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of AVTech AVC 7xx DVR devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.avtech.hk/english/products5_1_787.htm" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
port = http_get_port( default: 80 );
url = "/";
res = http_get_cache( port: port, item: url );
if( IsMatchRegexp( res, "Server:\\s*AV-TECH AV[0-9]+ Video Web Server" ) ) {
	hostType = "Video_Web_Server";
}
else {
	if(IsMatchRegexp( res, "Server:\\s*SQ-WEBCAM" )){
		hostType = "SQ_Webcam";
	}
}
if(IsMatchRegexp( res, "---\\s*VIDEO WEB SERVER\\s*---" ) && !isnull( hostType ) && ContainsString( res, ">Username<" ) && ContainsString( res, ">Password<" )){
	version = "unknown";
	install = "/";
	set_kb_item( name: "avtech/avc7xx/dvr/detected", value: TRUE );
	set_kb_item( name: "avtech/avc7xx/dvr/host_type", value: hostType );
	cpe = "cpe:/o:avtech:avc7xx_dvr_firmware";
	os_register_and_report( os: "AVTech AVC 7xx DVR Firmware", cpe: cpe, runs_key: "unixoide", desc: "AVTech AVC 7xx DVR Device Detection (HTTP)" );
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "AVTech AVC 7xx DVR", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: conclUrl, extra: "The version is not being sent by the host." );
}
exit( 0 );

