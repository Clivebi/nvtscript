if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902081" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-08-02 12:38:17 +0200 (Mon, 02 Aug 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Event Horizon Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_tag( name: "summary", value: "This script finds the installed Event Horizon version." );
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
for dir in nasl_make_list_unique( "/eventhorizon", "/eventh", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, ">Event Horizon<" )){
		version = "unknown";
		ver = eregmatch( pattern: ">Version ([0-9.]+)", string: rcvRes );
		if( isnull( ver[1] ) ){
			sndReq = http_get( item: dir + "/CHANGELOG", port: port );
			rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
			ver = eregmatch( pattern: "([0-9.]+)", string: rcvRes );
			if(!isnull( ver[1] )){
				version = ver[1];
			}
		}
		else {
			version = ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/Event/Horizon/Ver", value: tmp_version );
		set_kb_item( name: "event_horizon/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:jared_meeker:event_horizon:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:jared_meeker:event_horizon";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Event Horizon", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

