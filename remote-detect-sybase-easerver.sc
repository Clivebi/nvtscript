if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.80006" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-09-09 16:54:39 +0200 (Tue, 09 Sep 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Sybase Enterprise Application Server service detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Christian Eric Edjenguele <christian.edjenguele@owasp.org>" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The remote host is running the Sybase Enterprise Application Server.
  Sybase EAServer is the open application server from Sybase Inc
  an enterprise software and services company exclusively focused on managing and mobilizing information." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
require("cpe.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: port );
version = "unknown";
concluded = "";
if(( ContainsString( buf, "<TITLE>Sybase EAServer<" ) || egrep( pattern: "Sybase EAServer", string: buf ) )){
	identified = 1;
	ver = eregmatch( pattern: "EAServer ([0-9.]+)", string: buf );
	if(!isnull( ver[1] )){
		version = ver[1];
		concluded += "\n- " + ver[0];
	}
}
req = http_get( item: "/WebConsole/Login.jsp", port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(detectedConsole = eregmatch( string: buf, pattern: "Sybase Management Console Login" )){
	identified = 1;
	concluded += "\n- /WebConsole/Login.jsp";
	set_kb_item( name: "SybaseJSPConsole/installed", value: TRUE );
}
banner = http_get_remote_headers( port: port );
if(detectedBanner = eregmatch( string: banner, pattern: "Server: Jaguar Server Version([ 0-9.]+)", icase: TRUE )){
	identified = 1;
	concluded += "\n- " + detectedBanner[0];
}
if(identified){
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:sybase:easerver:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:sybase:easerver";
	}
	set_kb_item( name: "www/" + port + "/SybaseEAServer", value: version );
	set_kb_item( name: "SybaseEAServer/installed", value: TRUE );
	register_product( cpe: cpe, location: port + "/tcp", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Sybase Enterprise Application Server", version: version, install: port + "/tcp", cpe: cpe, concluded: concluded ), port: port );
}
exit( 0 );

