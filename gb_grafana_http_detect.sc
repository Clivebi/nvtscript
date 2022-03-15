if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113259" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-31 12:03:00 +0200 (Fri, 31 Aug 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Grafana Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 3000 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Checks if Grafana is running on the target system
  and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://grafana.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 3000 );
for location in nasl_make_list_unique( "/", "/grafana", http_cgi_dirs( port: port ) ) {
	url = location;
	if(url == "/"){
		url = "";
	}
	url = url + "/login";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "base href=\"[^\"]*/grafana/\"" ) || ContainsString( buf, "window.grafanaBootData" )){
		set_kb_item( name: "grafana/detected", value: TRUE );
		set_kb_item( name: "grafana/http/port", value: TRUE );
		version = "unknown";
		vers = eregmatch( string: buf, pattern: "Grafana v([0-9.]+) \\(" );
		if( !isnull( vers[1] ) ){
			version = vers[1];
		}
		else {
			vers = eregmatch( string: buf, pattern: "(latestversion|commit)[^,}]+,[\'\"]version[\'\"]:[\'\"]([0-9.]+)[\'\"]", icase: TRUE );
			if(!isnull( vers[2] )){
				version = vers[2];
			}
		}
		register_and_report_cpe( app: "Grafana", ver: version, concluded: vers[0], base: "cpe:/a:grafana:grafana:", expr: "^([0-9.]+)", insloc: location, regPort: port, conclUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ) );
		exit( 0 );
	}
}
exit( 0 );

