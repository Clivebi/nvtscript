if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107098" );
	script_version( "2021-09-10T08:53:21+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 08:53:21 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-02 14:04:20 +0200 (Tue, 02 May 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Emby Server Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8096 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of Emby Server." );
	script_xref( name: "URL", value: "https://emby.media/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8096 );
url = "/web/index.html";
res = http_get_cache( port: port, item: url );
if(ContainsString( res, "<title>Emby</title>" ) && ContainsString( res, "Energize your media" ) && ( ContainsString( res, "emby-input" ) || ContainsString( res, "\"application-name\" content=\"Emby\"" ) )){
	version = "unknown";
	vers = eregmatch( pattern: "\\.js\\?v=([0-9.]+)", string: res );
	if( !isnull( vers[1] ) ){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
	}
	else {
		url = "/System/Info/Public";
		res = http_get_cache( port: port, item: url );
		vers = eregmatch( pattern: "\"Version\":\"([0-9.]+)\"", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
	set_kb_item( name: "emby/media_server/detected", value: TRUE );
	set_kb_item( name: "emby/media_server/http/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:msf_emby_project:msf_emby:" );
	if(!cpe){
		cpe = "cpe:/a:msf_emby_project:msf_emby";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "Emby Server", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
	exit( 0 );
}
exit( 0 );

