if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800295" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-03-02 12:02:59 +0100 (Tue, 02 Mar 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Limny Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Limny.

  The script sends a connection request to the server and attempts to
  extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
limPort = http_get_port( default: 80 );
if(!http_can_host_php( port: limPort )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/limny", "/limny/upload", http_cgi_dirs( port: limPort ) ) {
	rep_dir = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: limPort );
	if(ContainsString( rcvRes, "Limny" )){
		limVer = eregmatch( pattern: "Limny ([0-9.]+)", string: rcvRes );
		if( limVer[1] ){
			version = limVer[1];
		}
		else {
			version = "Unknown";
		}
		tmp_version = version + " under " + rep_dir;
		set_kb_item( name: "www/" + limPort + "/Limny", value: tmp_version );
		set_kb_item( name: "limny/installed", value: TRUE );
		log_message( data: "Limny version " + version + " running at location " + rep_dir + " was detected on the host" );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:limny:limny:" );
		if(!cpe){
			cpe = "cpe:/a:limny:limny";
		}
		register_product( cpe: cpe, location: rep_dir, port: limPort, service: "www" );
		log_message( data: build_detection_report( app: "Limny", version: version, install: rep_dir, cpe: cpe, concluded: limVer[0] ), port: limPort );
	}
}
exit( 0 );

