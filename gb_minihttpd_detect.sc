if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140802" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-23 11:52:05 +0700 (Fri, 23 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "mini_httpd Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of mini_httpd.

  The script sends a connection request to the server and attempts to detect mini_httpd and to extract its
  version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_mandatory_keys( "mini_httpd/banner" );
	script_require_ports( "Services/www", 80, 443 );
	script_xref( name: "URL", value: "https://acme.com/software/mini_httpd/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port );
if(!banner){
	exit( 0 );
}
if(!concl = egrep( string: banner, pattern: "Server: mini_httpd", icase: TRUE )){
	exit( 0 );
}
concl = chomp( concl );
version = "unknown";
vers = eregmatch( pattern: "mini_httpd/([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
	concl = vers[0];
}
set_kb_item( name: "mini_httpd/installed", value: TRUE );
cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:acme:mini_httpd:" );
if(!cpe){
	cpe = "cpe:/a:acme:mini_httpd";
}
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( data: build_detection_report( app: "mini_httpd", version: version, install: "/", cpe: cpe, concluded: concl ), port: port );
exit( 0 );

