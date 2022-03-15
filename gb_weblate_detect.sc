if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106667" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-03-17 14:27:26 +0700 (Fri, 17 Mar 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Weblate Detection" );
	script_tag( name: "summary", value: "Detection of Weblate

The script sends a HTTP connection request to the server and attempts to detect the presence of Weblate and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://weblate.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/weblate", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	req = http_get( port: port, item: dir + "/about/" );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "<title>.*About Weblate.*</title>" ) && ContainsString( res, "\"panel-title\">Versions" )){
		version = "unknown";
		vers = eregmatch( pattern: "Weblate</a></th>.<td>([0-9.]+)</td>", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			set_kb_item( name: "weblate/version", value: version );
		}
		set_kb_item( name: "weblate/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:weblate:weblate:" );
		if(!cpe){
			cpe = "cpe:/a:weblate:weblate";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Weblate", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

