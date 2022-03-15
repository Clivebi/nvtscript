if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108008" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-10-26 14:47:00 +0200 (Wed, 26 Oct 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Pootle Server Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the server
  and attempts to extract the version from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/translate", "/pootle", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/about/";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, ">About this Pootle Server<" ) || ContainsString( buf, "<li>This Pootle Server</li>" ) || ContainsString( buf, "javascript:PTL.zoom.zoom" ) || ContainsString( buf, "<title>This Pootle Server" ) )){
		version = "unknown";
		ver = eregmatch( pattern: "<p>Pootle ([0-9.]+)(-([a-zA-Z]+)([0-9]+))? is powered", string: buf );
		if(!isnull( ver[1] )){
			version = ver[1];
			concludedUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			if(ver[2]){
				ver[2] = ereg_replace( pattern: "-", string: ver[2], replace: "." );
				version = ver[1] + ver[2];
			}
		}
		cpe = build_cpe( value: version, exp: "([0-9.a-zA-Z]+)", base: "cpe:/a:translatehouse:pootle:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:translatehouse:pootle";
		}
		set_kb_item( name: "www/" + port + "/pootle_server", value: version );
		set_kb_item( name: "pootle_server/installed", value: TRUE );
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Pootle Server", version: version, install: install, cpe: cpe, concluded: ver[0], concludedUrl: concludedUrl ), port: port );
	}
}
exit( 0 );

