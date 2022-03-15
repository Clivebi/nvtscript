if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103255" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-09-14 13:31:57 +0200 (Wed, 14 Sep 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "PHP Support Tickets Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.phpsupporttickets.com/" );
	script_tag( name: "summary", value: "This host is running PHP Support Tickets, a PHP5 / MySQL helpdesk
  system." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/tickets", "/support", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: port );
	if(isnull( buf )){
		continue;
	}
	if(egrep( pattern: "<title>PHP Support Tickets", string: buf, icase: TRUE )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "PHP Support Tickets v([0-9.]+)", icase: TRUE );
		if(!isnull( version[1] )){
			vers = chomp( version[1] );
		}
		set_kb_item( name: "www/" + port + "/php_support_tickets", value: vers + " under " + install );
		set_kb_item( name: "php_support_tickets/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:triangle_solutions:php_support_tickets:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:triangle_solutions:php_support_tickets";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "PHP Support Tickets", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

