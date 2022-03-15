if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103735" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2013-06-12 11:17:19 +0200 (Wed, 12 Jun 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Plone Detection" );
	script_tag( name: "summary", value: "Detection of Plone CMS.

The script sends a connection request to the server and attempts to detect the presence of Plone CMS and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
dirs = nasl_make_list_unique( "/plone", "/Plone", "/cms", http_cgi_dirs( port: port ) );
for dir in dirs {
	buf = http_get_cache( item: dir, port: port );
	if(egrep( pattern: "<meta name=\"generator\" content=\"Plone", string: buf, icase: TRUE )){
		version = "unknown";
		vers = eregmatch( pattern: "Server: .*Plone/([0-9.]+)", string: buf );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "plone/version", value: version );
		}
		set_kb_item( name: "plone/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:plone:plone:" );
		if(!cpe){
			cpe = "cpe:/a:plone:plone";
		}
		register_product( cpe: cpe, location: dir, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Plone CMS", version: version, install: dir, cpe: cpe, concluded: vers[0] ), port: port );
	}
}
exit( 0 );

