if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806527" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-11-02 18:23:47 +0530 (Mon, 02 Nov 2015)" );
	script_name( "PHP Server Monitor Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_require_ports( "Services/www", 80 );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  PHP Server Monitor.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/phpservermon", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( rcvRes, "Powered by.*PHP Server Monitor" ) && ContainsString( rcvRes, ">SERVER MONITOR" ) && ContainsString( rcvRes, ">Login" )){
		version = "unknown";
		ver = eregmatch( pattern: "PHP Server Monitor v([0-9.]+)", string: rcvRes );
		if(ver[1]){
			version = ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/PHP Server Monitor", value: tmp_version );
		set_kb_item( name: "PHP/Server/Monitor/Installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:phpserver:monitor:" );
		if(!cpe){
			cpe = "cpe:/a:phpserver:monitor";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "PHP Server Monitor", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

