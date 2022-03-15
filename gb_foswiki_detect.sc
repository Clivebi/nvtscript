if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800612" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-05-11 08:41:11 +0200 (Mon, 11 May 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Foswiki Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Foswiki.

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
for dir in nasl_make_list_unique( "/", "/foswiki", "/wiki", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/Main/WebHome", port: port );
	res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!ContainsString( res, "Powered by Foswiki" )){
		req = http_get( item: dir + "/bin/view/foswiki/WebHome", port: port );
		res = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	}
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Powered by Foswiki" )){
		version = "unknown";
		vers = eregmatch( pattern: "Foswiki-([0-9.]+)(,|</strong>)", string: res );
		if( !isnull( vers[1] ) ){
			version = vers[1];
		}
		else {
			vers = eregmatch( pattern: "Foswiki version <strong>v([0-9.]+)</strong>", string: res );
			if(!isnull( vers[1] )){
				version = vers[1];
			}
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/Foswiki", value: tmp_version );
		set_kb_item( name: "Foswiki/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:foswiki:foswiki:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:foswiki:foswiki";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Foswiki", version: version, install: install, cpe: cpe, concluded: vers[0] ), port: port );
	}
}
exit( 0 );

