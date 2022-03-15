if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103143" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2011-04-29 15:04:36 +0200 (Fri, 29 Apr 2011)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Dolibarr Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Dolibarr, an opensource ERP/CRM Software.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.dolibarr.org/" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
dolport = http_get_port( default: 80 );
if(!http_can_host_php( port: dolport )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/dolibarr", "/dolibarr/htdocs", "/htdocs", http_cgi_dirs( port: dolport ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/index.php";
	buf = http_get_cache( item: url, port: dolport );
	if(!buf){
		continue;
	}
	if(ContainsString( buf, "Set-Cookie: DOLSESSID" ) && ContainsString( buf, ( "<title>Login" || "<title>Dolibarr" ) ) && ContainsString( buf, ( "dolibarr_logo.png" || "dolibarr.org" ) )){
		vers = "unknown";
		version = eregmatch( string: buf, pattern: ">Dolibarr.{0,5} ([0-9.]+)<", icase: TRUE );
		if(!isnull( version[1] )){
			vers = version[1];
		}
		set_kb_item( name: "dolibarr/detected", value: TRUE );
		cpe = build_cpe( value: vers, exp: "^([0-9.]+)", base: "cpe:/a:dolibarr:dolibarr:" );
		if(!cpe){
			cpe = "cpe:/a:dolibarr:dolibarr";
		}
		register_product( cpe: cpe, location: install, port: dolport, service: "www" );
		log_message( data: build_detection_report( app: "Dolibarr ERP/CRM", version: vers, install: install, cpe: cpe, concluded: version[0] ), port: dolport );
		exit( 0 );
	}
}
exit( 0 );

