if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800413" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "JpGraph Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the running JpGraph version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
jgphPort = http_get_port( default: 80 );
for path in nasl_make_list_unique( "/", "/jpgraph", "/jpgraph/docportal", http_cgi_dirs( port: jgphPort ) ) {
	install = path;
	if(path == "/"){
		path = "";
	}
	rcvRes = http_get_cache( item: path + "/index.html", port: jgphPort );
	if(ContainsString( rcvRes, "JpGraph" )){
		version = "unknown";
		sndReq = http_get( item: path + "/../VERSION", port: jgphPort );
		rcvRes = http_keepalive_send_recv( port: jgphPort, data: sndReq, bodyonly: 1 );
		jgphVer = eregmatch( pattern: "v([0-9.]+)", string: rcvRes );
		if(jgphVer[1] != NULL){
			version = jgphVer[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + jgphPort + "/JpGraph", value: tmp_version );
		set_kb_item( name: "jpgraph/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:aditus:jpgraph:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:aditus:jpgraph";
		}
		register_product( cpe: cpe, location: install, port: jgphPort, service: "www" );
		log_message( data: build_detection_report( app: "Jp Graph", version: version, install: install, cpe: cpe, concluded: jgphVer[0] ), port: jgphPort );
	}
}

