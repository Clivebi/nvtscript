if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100376" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-12-21T02:40:42+0000" );
	script_tag( name: "last_modification", value: "2020-12-21 02:40:42 +0000 (Mon, 21 Dec 2020)" );
	script_tag( name: "creation_date", value: "2009-12-03 12:57:42 +0100 (Thu, 03 Dec 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "AWStats Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "HTTP based detection of AWStats." );
	script_xref( name: "URL", value: "http://awstats.sourceforge.net/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/", "/awstats", "/stats", "/logs", "/awstats/cgi-bin", "/statistics", "/statistik/cgi-bin", "/awstats-cgi", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	res = http_get_cache( port: port, item: dir + "/" );
	loc = eregmatch( pattern: "/awstats\\.pl\\?config=([a-z0-9.]+)", string: res, icase: TRUE );
	if( !isnull( loc[1] ) ) {
		url = dir + "/awstats.pl?config=" + loc[1] + "&framename=mainright";
	}
	else {
		url = dir + "/awstats.pl?framename=mainright";
	}
	req = http_get( item: url, port: port );
	buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
	if(!ContainsString( buf, "content=\"Awstats - Advanced Web Statistics" ) && !ContainsString( buf, "AWStats UseFramesWhenCGI" ) && !ContainsString( buf, "Created by awstats" ) && !ContainsString( buf, "CreateDirDataIfNotExists" ) && !ContainsString( buf, "content=\"AWStats " )){
		buf = http_get_cache( port: port, item: dir + "/" );
		if(!ContainsString( buf, "content=\"Awstats - Advanced Web Statistics" ) && !ContainsString( buf, "AWStats UseFramesWhenCGI" ) && !ContainsString( buf, "Created by awstats" ) && !ContainsString( buf, "CreateDirDataIfNotExists" ) && !ContainsString( buf, "content=\"AWStats " )){
			continue;
		}
	}
	if(ContainsString( buf, "content=\"Awstats - Advanced Web Statistics" ) || ContainsString( buf, "AWStats UseFramesWhenCGI" ) || ContainsString( buf, "Created by awstats" ) || ContainsString( buf, "CreateDirDataIfNotExists" ) || ContainsString( buf, "content=\"AWStats " )){
		version = "unknown";
		vers = eregmatch( string: buf, pattern: "Advanced Web Statistics ([0-9.]+)", icase: TRUE );
		if(isnull( vers[1] )){
			vers = eregmatch( pattern: "name=\"generator\" content=\"AWStats ([0-9.]+)", string: buf );
		}
		if(!isnull( vers[1] )){
			version = vers[1];
		}
		set_kb_item( name: "awstats/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:awstats:awstats:" );
		if(!cpe){
			cpe = "cpe:/a:awstats:awstats";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "AWStats", version: version, install: install, cpe: cpe, concluded: vers[0], concludedUrl: http_report_vuln_url( port: port, url: url, url_only: TRUE ) ), port: port );
		exit( 0 );
	}
}
exit( 0 );

