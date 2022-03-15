if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801209" );
	script_version( "2021-08-31T14:18:10+0000" );
	script_tag( name: "last_modification", value: "2021-08-31 14:18:10 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-05-25 13:56:16 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "PmWiki Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of PmWiki." );
	script_xref( name: "URL", value: "https://www.pmwiki.org/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in nasl_make_list_unique( "/", "/pmwiki", "/wiki", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/pmwiki.php" );
	if(IsMatchRegexp( res, "/pmwiki.php\\?n=(Main|PmWiki)" ) && ContainsString( res, "id='wikicmds'" )){
		version = "unknown";
		url = dir + "/pmwiki.php?n=PmWiki.ReleaseNotes";
		res = http_get_cache( port: port, item: url );
		vers = eregmatch( pattern: ">Version ([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
			concUrl = http_report_vuln_url( port: port, url: url, url_only: TRUE );
		}
		set_kb_item( name: "pmwiki/detected", value: TRUE );
		set_kb_item( name: "pmwiki/http/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:pmwiki:pmwiki:" );
		if(!cpe){
			cpe = "cpe:/a:pmwiki:pmwiki";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "PmWiki", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: concUrl ), port: port );
		exit( 0 );
	}
}
exit( 0 );

