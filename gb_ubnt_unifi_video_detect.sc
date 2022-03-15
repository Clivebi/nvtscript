if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114048" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-14 14:31:02 +0100 (Fri, 14 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Ubiquiti Networks UniFi Video Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of UniFi Video.

  The script sends a connection request to the server and attempts to detect UniFi Video and to
  extract its version if possible." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.ui.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/";
res = http_get_cache( port: port, item: url );
if( ContainsString( res, "content=\"app-id=com.ubnt.unifivideo\">" ) ){
	hostType = "Session";
}
else {
	if( ContainsString( res, "class=\"portal__controllerItem--unifi-video\">" ) ){
		hostType = "Portal";
	}
	else {
		if( ContainsString( res, "window.App = App.initialize({\"ENVIRONMENT\":\"NVR\",\"IS_PRODUCTION\":true,\"IS_CLOUD_FEATURE_ENABLED\":false});" ) ){
			hostType = "NoSessionEmail";
		}
		else {
			url = "/services/api.js";
			res = http_get_cache( port: port, item: url );
			if(ContainsString( res, "\"unifi\"===mode&&(mode=0)" )){
				hostType = "NoSession";
			}
		}
	}
}
if(!isnull( hostType )){
	version = "unknown";
	install = "/";
	res = http_get_cache( port: port, item: "/api/2.0/bootstrap" );
	ver = eregmatch( pattern: "\\{\"version\":\"([0-9.]+)\",", string: res );
	if(!isnull( ver[1] )){
		version = ver[1];
	}
	set_kb_item( name: "ubnt/unifi_video/detected", value: TRUE );
	set_kb_item( name: "ubnt/unifi_video/hostType", value: hostType );
	cpe = "cpe:/a:ui:unifi_video:";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "UniFi Video", ver: version, concluded: ver[0], base: cpe, expr: "^([0-9.]+)", insloc: install, regPort: port, regService: "www", conclUrl: conclUrl );
}
exit( 0 );

