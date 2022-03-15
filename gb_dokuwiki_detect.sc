if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800587" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-06-19 09:45:44 +0200 (Fri, 19 Jun 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "DokuWiki Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of DokuWiki.

  The script sends a connection request to the server and attempts to extract the
  version number from the reply." );
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
if(!http_can_host_php( port: port )){
	exit( 0 );
}
rootInstalled = FALSE;
for dir in nasl_make_list_unique( "/", "/wiki", "/dokuwiki", http_cgi_dirs( port: port ) ) {
	if(rootInstalled){
		break;
	}
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	req = http_get( item: dir + "/feed.php", port: port );
	rcv = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	req = http_get( item: dir + "/doku.php", port: port );
	rcv2 = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
	if(( !ContainsString( rcv, "generator=\"FeedCreator" ) && !ContainsString( rcv, "DokuWiki\"" ) ) && !ContainsString( rcv, "Set-Cookie: DokuWiki=" ) && !ContainsString( rcv, "<error>RSS feed is disabled.</error>" ) && !ContainsString( rcv2, "Driven by DokuWiki" ) && !ContainsString( rcv2, "generator\" content=\"DokuWiki" )){
		continue;
	}
	if(dir == ""){
		rootInstalled = TRUE;
	}
	set_kb_item( name: "dokuwiki/installed", value: TRUE );
	version = "unknown";
	if(ContainsString( rcv2, "://www.dokuwiki.org/update_check" ) && ( ContainsString( rcv2, "<div class=\"notify\">" ) || ContainsString( rcv2, "<div class=\"msg notify\">" ) )){
		set_kb_item( name: "dokuwiki/missing_updates/" + port + install, value: TRUE );
		set_kb_item( name: "dokuwiki/missing_updates", value: TRUE );
	}
	vers = eregmatch( pattern: "DokuWiki Release (rc([0-9\\-])?)?([0-9]{4}\\-[0-9]{2}\\-[0-9]{2}[a-z]?)", string: rcv2 );
	if( !vers[3] ){
		url = dir + "/VERSION";
		req = http_get( item: url, port: port );
		rcv2 = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		vers = eregmatch( pattern: "(rc([0-9\\-])?)?([0-9]{4}\\-[0-9]{2}\\-[0-9]{2}[a-z]?)", string: rcv2 );
		if(!isnull( vers[3] )){
			version = vers[3];
			conclUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
	}
	else {
		version = vers[3];
	}
	cpe = build_cpe( value: version, exp: "^([0-9\\-]+[a-z]?)", base: "cpe:/a:dokuwiki:dokuwiki:" );
	if(isnull( cpe )){
		cpe = "cpe:/a:dokuwiki:dokuwiki";
	}
	register_product( cpe: cpe, location: install, port: port, service: "www" );
	log_message( data: build_detection_report( app: "DokuWiki", version: version, install: install, cpe: cpe, concludedUrl: conclUrl, concluded: vers[0] ), port: port );
}
exit( 0 );

