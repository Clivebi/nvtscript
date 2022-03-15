if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105137" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-12-08 10:46:34 +0100 (Mon, 08 Dec 2014)" );
	script_name( "Zarafa WebApp Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends a connection
  request to the server and attempts to extract the version number
  from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for url in make_list( "/",
	 "/webapp" ) {
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(ContainsString( buf, "<title>Zarafa WebApp" )){
		set_kb_item( name: "zarafa_webapp/installed", value: TRUE );
		set_kb_item( name: "zarafa/installed", value: TRUE );
		vers = "unknown";
		version = eregmatch( pattern: "<span id=\"version\">WebApp ([^ <]+)( - ZCP ([^<]+))?</span>", string: buf );
		if(!isnull( version[1] )){
			vers = version[1];
			set_kb_item( name: "zarafa_webapp/installed", value: TRUE );
			cpe = build_cpe( value: vers, exp: "^([0-9.-]+)", base: "cpe:/a:zarafa:webapp:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:zarafa:webapp";
			}
			cpe = str_replace( string: cpe, find: "-", replace: "." );
			register_product( cpe: cpe, location: url, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Zarafa WebApp", version: vers, install: url, cpe: cpe, concluded: version[0] ), port: port );
		}
		if(!isnull( version[3] )){
			vers_zcp = version[3];
			set_kb_item( name: "zarafa_zcp/installed", value: TRUE );
			set_kb_item( name: "zarafa/installed", value: TRUE );
			cpe = build_cpe( value: vers_zcp, exp: "^([0-9.-]+)", base: "cpe:/a:zarafa:zarafa_collaboration_platform:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:zarafa:zarafa_collaboration_platform";
			}
			cpe = str_replace( string: cpe, find: "-", replace: "." );
			register_product( cpe: cpe, location: url, port: port, service: "www" );
			log_message( data: build_detection_report( app: "Zarafa Collaboration Platform", version: vers_zcp, install: url, cpe: cpe, concluded: version[0] ), port: port );
		}
	}
}

