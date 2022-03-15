if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114020" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-15 13:48:08 +0200 (Wed, 15 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Sanyo Network Camera Detection" );
	script_tag( name: "summary", value: "Detection of Sanyo Network Camera.

  The script sends a connection request to the server and attempts to detect Sanyo Network Camera." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.sourcesecurity.com/ip-cameras/make.mk-454-ga.html" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
res = http_get_cache( port: port, item: "/" );
if(( ContainsString( res, "<TITLE>SANYO NETWORK CAMERA</TITLE>" ) && ContainsString( res, "AUTHENTICATION ERROR</TD>" ) && ContainsString( res, "Please input a correct user name/password</TD>" ) ) || ContainsString( res, "<IMG src=\"../img/SANYO_lan.gif\"></TD>" ) && ContainsString( res, "<IMG src=\"../img/info_lan.gif\"></TD>" )){
	version = "unknown";
	install = "/";
	conclUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	set_kb_item( name: "sanyo/network_camera/detected", value: TRUE );
	set_kb_item( name: "sanyo/network_camera/" + port + "/detected", value: TRUE );
	register_and_report_cpe( app: "Sanyo Network Camera", ver: version, base: "cpe:/h:sanyo:network_camera:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: conclUrl, extra: "Login required for version detection." );
}
exit( 0 );

