if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100093" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-03-31 18:59:35 +0200 (Tue, 31 Mar 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Bugzilla Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_family( "Product detection" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Bugzilla.

The script sends a connection request to the server and attempts to extract the version number from the reply." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/bugzilla", "/bugs", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.cgi";
	buf = http_get_cache( port: port, item: url );
	if(egrep( pattern: "Bugzilla_login", string: buf ) && egrep( pattern: "Bugzilla_password", string: buf )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: "version ([0-9.]+)(.?rc([0-9]+)?)?", icase: TRUE );
		if(!isnull( version[1] )){
			if(!isnull( version[2] )){
				vers = version[1] + "." + version[2];
			}
		}
		if( isnull( version[1] ) ){
			url = dir + "/docs/en/txt/Bugzilla-Guide.txt";
			req = http_get( item: url, port: port );
			buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			version = eregmatch( string: buf, pattern: "The Bugzilla Guide - ([0-9.]+)(.?rc([0-9]+)?)? Release" );
			if( !isnull( version[1] ) ){
				if(!isnull( version[2] )){
					vers = version[1] + "." + version[2];
				}
				concUrl = url;
			}
			else {
				url = dir + "/CVS/Tag";
				req = http_get( item: url, port: port );
				buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
				if(!isnull( buf )){
					version = eregmatch( string: buf, pattern: "BUGZILLA-([0-9._]+)(.?rc([0-9]+)?)? Release" );
					if(!isnull( version[1] )){
						if(version[1] = ereg_replace( pattern: "_", string: version[1], replace: "." )){
							if(!isnull( version[2] )){
								vers = version[1] + "." + version[2];
							}
						}
						concUrl = url;
					}
				}
			}
		}
		else {
			vers = version[1];
		}
		set_kb_item( name: "bugzilla/installed", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9._]+)", base: "cpe:/a:mozilla:bugzilla:" );
		if(!cpe){
			cpe = "cpe:/a:mozilla:bugzilla";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Bugzilla", version: vers, install: install, cpe: cpe, concluded: version[0], concludedUrl: concUrl ), port: port );
	}
}
exit( 0 );

