if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105181" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-01-22 12:00:00 +0100 (Thu, 22 Jan 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Vaadin Framework Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8888 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the server and
  attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 8888 );
for dir in nasl_make_list_unique( "/", "/sampler", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "vaadinVersion" ) || ContainsString( buf, "/VAADIN/themes/" ) || ( ContainsString( buf, "v-verticallayout" ) && ContainsString( buf, "v-horizontallayout" ) ) )){
		concludedUrl = "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
		version = "unknown";
		ver = eregmatch( pattern: "vaadinVersion(\": \"|\":\")([0-9.]+[0-9.]+[0-9])", string: buf );
		if( !isnull( ver[2] ) ){
			version = ver[2];
		}
		else {
			style = eregmatch( pattern: "<link.*rel=.*href=\"(./|/)(VAADIN/themes/)([0-9a-zA-Z]+)/", string: buf );
			if(!isnull( style[2] ) && !isnull( style[3] )){
				if( style[1] == "./" ){
					url = dir + "/" + style[2] + style[3] + "/styles.css";
				}
				else {
					url = "/" + style[2] + style[3] + "/styles.css";
				}
				req = http_get( item: url, port: port );
				res = http_keepalive_send_recv( port: port, data: req );
				ver = eregmatch( pattern: ".v-vaadin-version:after.*content: \"([0-9.]+)\";", string: res );
				if(!isnull( ver[1] )){
					version = ver[1];
					concludedUrl = "\n" + http_report_vuln_url( port: port, url: url, url_only: TRUE );
				}
			}
		}
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:vaadin:vaadin:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:vaadin:vaadin";
		}
		set_kb_item( name: "www/" + port + "/vaadin", value: version );
		set_kb_item( name: "vaadin/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Vaadin Framework", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concludedUrl ), port: port );
	}
}
exit( 0 );

