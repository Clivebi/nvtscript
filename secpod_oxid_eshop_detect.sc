if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900932" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-11 18:01:06 +0200 (Fri, 11 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "OXID eShop Community Edition Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script detects the installed version of OXID eShop." );
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
for dir in nasl_make_list_unique( "/", "/oxid", "/eshop", "/oxid-eshop", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/admin/", port: port );
	if(ContainsString( res, "OXID eShop Login" ) && IsMatchRegexp( res, "OXID eShop (Enterprise|Professional|Community)" )){
		version = "unknown";
		ver = eregmatch( pattern: "Version ([0-9.]+)", string: res );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		ed = eregmatch( pattern: "OXID eShop (Enterprise|Professional|Community)", string: res );
		if(!isnull( ed[1] )){
			edition = ed[1];
			set_kb_item( name: "oxid_eshop/edition", value: edition );
		}
		set_kb_item( name: "oxid_eshop/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:oxid:eshop:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:oxid:eshop";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "OXID eShop " + edition + " Edition", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

