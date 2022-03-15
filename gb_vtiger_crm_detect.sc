if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100909" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-11-18 13:10:44 +0100 (Thu, 18 Nov 2010)" );
	script_name( "vtiger CRM Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_require_ports( "Services/www", 80, 8888 );
	script_tag( name: "summary", value: "Detection of Symantec vtiger CRM.

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
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/vtigercrm", "/crm", "/", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(( ContainsString( buf, "<title>vtiger CRM" ) && ( ContainsString( buf, "login_language" ) || ContainsString( buf, ">Powered by vtiger" ) ) ) || ( ContainsString( buf, "<title>Vtiger" ) && ContainsString( buf, "Powered by vtiger CRM" ) ) || ( ContainsString( buf, "Powered by vtiger CRM" ) && ContainsString( buf, "target=\"_blank\">Privacy Policy</a>" ) )){
		version = "unknown";
		ver = eregmatch( string: buf, pattern: "vtiger CRM[\\ ]?+[-]?[\\ ]?+([0-9.]+)([^ ]| RC)", icase: TRUE );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		set_kb_item( name: "vtiger/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:vtiger:vtiger_crm:" );
		if(!cpe){
			cpe = "cpe:/a:vtiger:vtiger_crm";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "vtiger CRM", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

