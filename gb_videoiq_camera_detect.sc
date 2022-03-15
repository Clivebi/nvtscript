if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807357" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-23 15:56:59 +0530 (Tue, 23 Aug 2016)" );
	script_name( "VideoIQ Camera Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  VideoIQ Camera.

  This script sends an HTTP GET request and tries to ensure the presence of
  VideoIQ Camera." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
url = "/?wicket:bookmarkablePage=:com.videoiq.fusion.camerawebapi.ui.pages.LoginPage";
req = http_get( item: url, port: port );
res = http_send_recv( port: port, data: req );
if(ContainsString( res, "<title>VideoIQ Camera Login</title>" ) && ContainsString( res, ">User name" ) && ContainsString( res, ">Password" ) && ContainsString( res, ">Login" )){
	version = "unknown";
	set_kb_item( name: "videoiq/camera/detected", value: TRUE );
	set_kb_item( name: "videoiq/camera/" + port + "/detected", value: TRUE );
	cpe = "cpe:/a:videoiq:videoiq_camera:";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "VideoIQ Camera", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, conclUrl: conclUrl );
}
exit( 0 );

