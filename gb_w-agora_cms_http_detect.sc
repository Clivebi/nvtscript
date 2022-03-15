if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.146182" );
	script_version( "2021-06-28T11:26:56+0000" );
	script_tag( name: "last_modification", value: "2021-06-28 11:26:56 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "creation_date", value: "2021-06-28 09:54:18 +0000 (Mon, 28 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "W-Agora CMS Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of W-Agora CMS." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.w-agora.net/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("list_array_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
for dir in nasl_make_list_unique( "/", "/w-agora", "/cms", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	res = http_get_cache( port: port, item: url );
	if(ContainsString( res, "Content=\"w-agora" )){
		version = "unknown";
		vers = eregmatch( pattern: "\"w-agora version ([0-9.]+)\"", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "w-agora/detected", value: TRUE );
		set_kb_item( name: "w-agora/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:w-agora:w-agora:" );
		if(!cpe){
			cpe = "cpe:/a:w-agora:w-agora";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "W-Agora CMS", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

