if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141470" );
	script_version( "2021-02-08T08:31:12+0000" );
	script_tag( name: "last_modification", value: "2021-02-08 08:31:12 +0000 (Mon, 08 Feb 2021)" );
	script_tag( name: "creation_date", value: "2018-09-12 14:04:42 +0700 (Wed, 12 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PacsOne Detection" );
	script_tag( name: "summary", value: "Detection of PacsOne Server.

The script sends a connection request to the server and attempts to detect PacsOne Server and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.pacsone.net" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/pacsone", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/login.php" );
	if(( ContainsString( res, "PacsOne Server" ) || ContainsString( res, "Not authorized to access this" ) ) && ( ContainsString( res, "Enter Anti-Spam Code From Below" ) || ContainsString( res, "Select Database:" ) )){
		version = "unknown";
		vers = eregmatch( pattern: "PacsOne Server ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "pacsone/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:rainbowfish:pacsone:" );
		if(!cpe){
			cpe = "cpe:/a:rainbowfish:pacsone";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "PacsOne", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

