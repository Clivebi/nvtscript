if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800437" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-01-22 09:23:45 +0100 (Fri, 22 Jan 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "phpNagios Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script finds the running phpNagios version." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/phpNagios", "/phpnagios", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	rcvRes = http_get_cache( item: dir + "/index.php", port: port );
	if(ContainsString( rcvRes, "<title>phpNagios</title>" ) || ContainsString( rcvRes, "<td>Nagios Version" )){
		version = "unknown";
		ver = eregmatch( pattern: "Nagios Version : ([0-9.]+)", string: rcvRes );
		if(!isnull( ver[1] )){
			extra = "Supported Nagios Version: " + ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/phpNagios", value: tmp_version );
		set_kb_item( name: "phpnagios/detected", value: TRUE );
		cpe = "cpe:/a:phpnagios:phpnagios";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "phpNagios", version: version, install: install, cpe: cpe, extra: extra ), port: port );
	}
}
exit( 0 );

