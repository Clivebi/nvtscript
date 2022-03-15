if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108453" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-08-04 11:09:44 +0200 (Sat, 04 Aug 2018)" );
	script_name( "Threema Web Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://github.com/threema-ch/threema-web/" );
	script_tag( name: "summary", value: "Detection of Threema Web.

  The script sends a connection request to the server and attempts to
  identify an installed Threema Web from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
buf = http_get_cache( item: "/", port: port );
if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ( ContainsString( buf, "<title>Threema Web</title>" ) || ContainsString( buf, "This file is part of Threema Web." ) || ContainsString( buf, "content=\"Chat from your desktop with Threema Web and have full access to all chats, contacts and media files.\"" ) )){
	install = "/";
	version = "unknown";
	set_kb_item( name: "threema-web/detected", value: TRUE );
	vers = eregmatch( string: buf, pattern: "(showVersionInfo\\('|>Version )([0-9.]+)[^/]+" );
	if(vers[2]){
		version = vers[2];
	}
	if(version == "unknown"){
		url = "/version.txt";
		res = http_get_cache( port: port, item: url );
		if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
			req = http_get( port: port, item: url );
			res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
			vers = eregmatch( string: res, pattern: "^([0-9.]+)(-gh)?" );
			if(vers[1]){
				version = vers[1];
				conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
			}
		}
	}
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:threema:threema_web:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:threema:threema_web";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "Threema Web", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: conclUrl ), port: port );
}
exit( 0 );

