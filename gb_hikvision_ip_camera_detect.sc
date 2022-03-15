if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114037" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-10-05 14:33:50 +0200 (Fri, 05 Oct 2018)" );
	script_name( "Hikvision IP Camera Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8081 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of the
  Hikvision IP Camera web interface.

  This script sends an HTTP GET request and tries to ensure the presence of
  the Hikvision IP Camera web interface." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8081 );
url = "/doc/script/config/system/channelDigital.js";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "<u>The requested resource is not available.</u>" ) || ContainsString( res, "Document Error: Not Found" ) || ContainsString( res, "HTTP/1.1 404 Not Found" )){
	url = "/doc/script/inc.js";
	res = http_get_cache( port: port, item: url );
}
if(ContainsString( res, "\"/hikvision://\"" ) || ContainsString( res, "{case\"HIKVISION\"" )){
	version = "unknown";
	url2 = "/doc/script/global_config.js";
	res = http_get_cache( port: port, item: url2 );
	if(ContainsString( res, "<u>The requested resource is not available.</u>" ) || ContainsString( res, "Document Error: Not Found" ) || ContainsString( res, "HTTP/1.1 404 Not Found" )){
		url2 = "/doc/script/lib/seajs/config/sea-config.js";
		res = http_get_cache( port: port, item: url2 );
	}
	ver = eregmatch( pattern: "seajs.web_version\\s*=\\s*\"V([0-9.]+)[a-zA-Z]+([0-9]+)\"|web_version:\\s?\"([0-9.]+)\"", string: res );
	if(!isnull( ver[1] ) && !isnull( ver[2] )){
		version = ver[1] + "." + ver[2];
	}
	if(!isnull( ver[3] )){
		version = ver[3];
	}
	set_kb_item( name: "hikvision/ip_camera/detected", value: TRUE );
	set_kb_item( name: "hikvision/ip_camera/" + port + "/detected", value: TRUE );
	set_kb_item( name: "hikvision/ip_camera/version", value: version );
	cpe = "cpe:/a:hikvision:ip_camera:";
	conclUrl = http_report_vuln_url( port: port, url: url2, url_only: TRUE );
	register_and_report_cpe( app: "Hikvision IP Camera", ver: version, base: cpe, expr: "^([0-9.a-z]+)", insloc: "/", regPort: port, conclUrl: conclUrl );
}
exit( 0 );

