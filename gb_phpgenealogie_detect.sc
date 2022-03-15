if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801007" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-10-08 08:22:29 +0200 (Thu, 08 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "PHPGenealogie Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of PHPGenealogie." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
phpgenPort = http_get_port( default: 80 );
if(!http_can_host_php( port: phpgenPort )){
	exit( 0 );
}
for path in nasl_make_list_unique( "/geneald", "/genealogie_sql", "/genealogie", http_cgi_dirs( port: phpgenPort ) ) {
	install = path;
	if(path == "/"){
		path = "";
	}
	sndReq = http_get( item: path + "/Index2.php", port: phpgenPort );
	rcvRes = http_keepalive_send_recv( port: phpgenPort, data: sndReq );
	if(ContainsString( rcvRes, "\">php.genealogie" )){
		version = "unknown";
		phpgenVer = eregmatch( pattern: "> ([0-9.]+)", string: rcvRes );
		if(phpgenVer[1] != NULL){
			version = phpgenVer[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + phpgenPort + "/PHPGenealogie", value: tmp_version );
		set_kb_item( name: "phpgenealogie/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:phpgenealogy:phpgenealogy:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:phpgenealogy:phpgenealogy";
		}
		register_product( cpe: cpe, location: install, port: phpgenPort, service: "www" );
		log_message( data: build_detection_report( app: "PHPGenealogie", version: version, install: install, cpe: cpe, concluded: phpgenVer[0] ), port: phpgenPort );
	}
}

