if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114027" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-29 10:46:20 +0200 (Wed, 29 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Axis Camera Station Detection" );
	script_tag( name: "summary", value: "Detection of Axis Camera Station Web UI.

  The script sends a connection request to the server and attempts to detect the installation of Axis Camera Station." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.axis.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 80 );
res1 = http_get_cache( port: port, item: "/axis-cgi/prod_brand_info/getbrand.cgi" );
if(ContainsString( res1, "\"Brand\": \"AXIS\"" ) && ContainsString( res1, "\"ProdFullName\":" ) && ContainsString( res1, "\"ProdFullName\":" ) && ContainsString( res1, "\"ProdNbr\":" ) && ContainsString( res1, "\"ProdType\":" )){
	version = "unknown";
	install = "/";
	req = http_get_req( port: port, url: "/js/bootstrap.js", add_headers: make_array( "Accept-Encoding", "gzip, deflate" ) );
	res2 = http_keepalive_send_recv( port: port, data: req );
	vers = eregmatch( pattern: "version:\"([0-9a-zA-Z.-]+)\"", string: res2 );
	if(vers[1]){
		version = vers[1];
	}
	conclUrl = http_report_vuln_url( port: port, url: "/", url_only: TRUE );
	set_kb_item( name: "axis/camerastation/detected", value: TRUE );
	set_kb_item( name: "axis/camerastation/" + port + "/detected", value: TRUE );
	set_kb_item( name: "axis/camerastation/web/version", value: version );
	register_and_report_cpe( app: "Axis Camera Station", ver: version, base: "cpe:/a:axis:camera_station:", expr: "^([0-9a-zA-Z.-]+)", insloc: install, regPort: port, conclUrl: conclUrl );
}
exit( 0 );

