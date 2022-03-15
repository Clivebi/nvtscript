if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114067" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-02-06 13:39:57 +0100 (Wed, 06 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Planet IP Camera Detection" );
	script_tag( name: "summary", value: "Detection of Planet IP Camera.

  The script sends a connection request to the server and attempts to detect the web interface for Planet's IP camera." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.planet.com.tw/en/products/ip-surveillance" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/scripts/lan_0_m.xml";
res = http_get_cache( port: port, item: url );
if(!ContainsString( res, "PLANET Techonolgy Co., LTD.:</copyright>" )){
	url = "/";
	res = http_get_cache( port: port, item: url );
}
if(ContainsString( res, "PLANET Techonolgy Co., LTD.:</copyright>" ) || ContainsString( res, "WWW-Authenticate: Basic realm=\"PLANET IP CAM\"" )){
	version = "unknown";
	install = "/";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	cpe = "cpe:/a:planet:ip_camera:";
	set_kb_item( name: "planet/ip_camera/detected", value: TRUE );
	set_kb_item( name: "planet/ip_camera/" + port + "/detected", value: TRUE );
	register_and_report_cpe( app: "Planet IP Camera", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: conclUrl, extra: "Version detection requires login." );
}
exit( 0 );

