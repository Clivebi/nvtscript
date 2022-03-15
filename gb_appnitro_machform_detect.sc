if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141125" );
	script_version( "2021-07-07T08:27:23+0000" );
	script_tag( name: "last_modification", value: "2021-07-07 08:27:23 +0000 (Wed, 07 Jul 2021)" );
	script_tag( name: "creation_date", value: "2018-05-31 09:43:00 +0700 (Thu, 31 May 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Appnitro MachForm Detection (HTTP)" );
	script_tag( name: "summary", value: "HTTP based detection of Appnitro MachForm." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.machform.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/machform", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/index.php" );
	if(ContainsString( res, "<title>MachForm Admin Panel</title>" ) && ContainsString( res, "Sign in below to create or edit your forms" )){
		version = "unknown";
		set_kb_item( name: "appnitro/machform/detected", value: TRUE );
		set_kb_item( name: "appnitro/machform/http/detected", value: TRUE );
		cpe = "cpe:/a:appnitro:machform";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Appnitro MachForm", version: version, install: install, cpe: cpe ), port: port );
		exit( 0 );
	}
}
exit( 0 );

