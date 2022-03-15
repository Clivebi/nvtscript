if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143150" );
	script_version( "2020-11-27T13:21:49+0000" );
	script_tag( name: "last_modification", value: "2020-11-27 13:21:49 +0000 (Fri, 27 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-11-20 04:03:51 +0000 (Wed, 20 Nov 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Tautulli Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Tautulli." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc" );
	script_mandatory_keys( "CherryPy/banner" );
	script_require_ports( "Services/www", 8181 );
	script_xref( name: "URL", value: "https://tautulli.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 8181 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "CherryPy" )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/tautulli", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/home";
	res = http_get_cache( port: port, item: url );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 303" )){
		for(i = 0;i < 2;i++){
			location = http_extract_location_from_redirect( port: port, data: res, current_dir: url );
			if(isnull( location )){
				break;
			}
			req = http_get( port: port, item: location );
			res = http_keepalive_send_recv( port: port, data: req );
			if(!IsMatchRegexp( res, "HTTP/1\\.[01] 303" )){
				break;
			}
		}
	}
	if(IsMatchRegexp( res, "<title>Tautulli - (Home|Login)" ) && ContainsString( res, "content=\"Tautulli\"" )){
		version = "unknown";
		url = dir + "/settings";
		req = http_get( port: port, item: url );
		res = http_keepalive_send_recv( port: port, data: req );
		vers = eregmatch( pattern: "Version v([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		if(ContainsString( res, "http_plex_admin" ) && ContainsString( res, "http_password" )){
			set_kb_item( name: "tautulli/" + port + "/noauth", value: TRUE );
		}
		token = eregmatch( pattern: "name=\"pms_token\" value=\"([^\"]+)\"", string: res );
		if(!isnull( token[1] )){
			set_kb_item( name: "tautulli/plex_token", value: token[1] );
		}
		set_kb_item( name: "tautulli/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:tautulli:tautulli:" );
		if(!cpe){
			cpe = "cpe:/a:tautulli:tautulli";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Tautulli", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

