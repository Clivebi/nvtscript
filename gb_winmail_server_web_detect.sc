if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141490" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-09-19 13:59:48 +0700 (Wed, 19 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Winmail Server Detection (HTTP)" );
	script_tag( name: "summary", value: "Detection of Winmail Server Webmail.

The script sends a connection HTTP based request to the server and attempts to detect Winmail Server Webmail and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 443, 8080, 6080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "http://www.magicwinmail.net/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 6080 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
url = "/admin/index.php";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "Powered by Winmail Server" ) && ContainsString( res, "Set-Cookie: magicwinmail" )){
	version = "unknown";
	vers = eregmatch( pattern: "Winmail( Mail)? Server ([0-9.]+)(\\(Build ([0-9]+)\\))?", string: res );
	if(!isnull( vers[2] )){
		version = vers[2];
		concUrl = url;
		if(!isnull( vers[4] )){
			extra = "Build:   " + vers[4];
			set_kb_item( name: "winmail_server/build", value: vers[4] );
		}
	}
	set_kb_item( name: "winmail_server/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:magicwinmail:winmail_server:" );
	if(!cpe){
		cpe = "cpe:/a:magicwinmail:winmail_server";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Winmail Server Webmail", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra ), port: port );
	exit( 0 );
}
exit( 0 );

