if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812511" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-08 11:46:24 +0530 (Thu, 08 Feb 2018)" );
	script_name( "Odoo Management Software Remote Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detects the installed version of
  Odoo management software.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/Odoo", "/odoo_cms", "/odoo_cmr", "/CMR", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( item: dir + "/web/login", port: port );
	if(ContainsString( res, "Log in with Odoo.com" ) && ( IsMatchRegexp( res, "(P|p)owered by.*>Odoo" ) || ContainsString( res, "content=\"Odoo" ) ) && ContainsString( res, ">Log in" )){
		version = "unknown";
		set_kb_item( name: "Odoo/Detected", value: TRUE );
		cpe = "cpe:/a:odoo:odoo";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Odoo", version: version, install: install, cpe: cpe ), port: port );
		exit( 0 );
	}
}
exit( 0 );

