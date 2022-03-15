if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114046" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-11-12 19:06:20 +0100 (Mon, 12 Nov 2018)" );
	script_name( "Samsung Web Viewer DVR Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installation of Samsung Web Viewer DVR.

  This script sends an HTTP GET request and tries to ensure the presence of
  Samsung Web Viewer DVR." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
url = "/js/language_webviewer.js";
res = http_get_cache( port: port, item: url );
if(IsMatchRegexp( res, "<h1>404\\s*-\\s*Not Found</h1>" )){
	url = "/cgi-bin/webviewer_login_page?lang=en&loginvalue=0&port=0";
	res = http_get_cache( port: port, item: url );
}
if(IsMatchRegexp( res, "\\[\\s*\"Web Viewer for Samsung DVR" ) || ( ContainsString( res, "/language_webviewer.js\"></script>" ) && ContainsString( res, "function setcookie(){" ) )){
	version = "unknown";
	set_kb_item( name: "samsung/web_viewer/dvr/detected", value: TRUE );
	set_kb_item( name: "samsung/web_viewer/dvr/" + port + "/detected", value: TRUE );
	cpe = "cpe:/a:samsung:web_viewer_dvr:";
	conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	register_and_report_cpe( app: "Samsung Web Viewer DVR", ver: version, base: cpe, expr: "^([0-9.]+)", insloc: "/", regPort: port, regService: "www", conclUrl: conclUrl );
}
exit( 0 );

