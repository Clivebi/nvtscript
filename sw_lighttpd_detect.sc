if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.111079" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-01-27 11:00:00 +0100 (Wed, 27 Jan 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Lighttpd Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 SCHUTZWERK GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "lighttpd/banner" );
	script_tag( name: "summary", value: "The script sends a HTTP request to the
  server and attempts to identify a Lighttpd Server and its version from the reply." );
	script_xref( name: "URL", value: "http://www.lighttpd.net" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(concl = egrep( string: banner, pattern: "Server: lighttpd", icase: TRUE )){
	concl = chomp( concl );
	version = "unknown";
	install = port + "/tcp";
	ver = eregmatch( pattern: "Server: lighttpd/([0-9.]+)(-[0-9.]+)?", string: banner, icase: TRUE );
	if(ver[1]){
		version = ver[1];
		concl = ver[0];
		if(ver[2]){
			ver[2] = ereg_replace( string: ver[2], pattern: "-", replace: "." );
			version = version + ver[2];
		}
	}
	set_kb_item( name: "www/" + port + "/lighttpd", value: version );
	set_kb_item( name: "lighttpd/installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:lighttpd:lighttpd:" );
	if(!cpe){
		cpe = "cpe:/a:lighttpd:lighttpd";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Lighttpd", version: version, install: install, cpe: cpe, concluded: concl ), port: port );
}
exit( 0 );

