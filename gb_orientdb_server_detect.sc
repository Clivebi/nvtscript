if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808753" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-08-08 15:37:50 +0530 (Mon, 08 Aug 2016)" );
	script_name( "OrientDB Server Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 2480 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of installed version
  of OrientDB Server.

  This script sends an HTTP GET request and tries to ensure the presence of
  OrientDB Server from the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = http_get_port( default: 2480 );
host = http_host_name( dont_add_port: TRUE );
found = FALSE;
version = "unknown";
banner = http_get_remote_headers( port: port );
if(ContainsString( banner, "OrientDB Server" )){
	found = TRUE;
	if(vers = eregmatch( pattern: "OrientDB Server v.([0-9.]+)", string: banner )){
		version = vers[1];
	}
}
if(!found || version == "unknown"){
	buf = http_get_cache( port: port, item: "/server/version" );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && ContainsString( buf, "OrientDB Server" )){
		found = TRUE;
	}
	if(vers = eregmatch( pattern: "([0-9.]+)$", string: buf )){
		version = vers[1];
		concUrl = http_report_vuln_url( port: port, url: "/server/version", url_only: TRUE );
	}
}
if(found){
	buf = http_get_cache( item: "/listDatabases", port: port );
	if(dbs = eregmatch( pattern: "\"databases\":\\[(.*)\\]", string: buf )){
		databases = split( buffer: dbs[1], sep: ",", keep: FALSE );
		set_kb_item( name: "OrientDB/" + host + "/" + port + "/databases", value: dbs[1] );
		extra = "The following databases were found on the OrientDB Server:\n";
		for database in databases {
			database = str_replace( string: database, find: "\"", replace: "" );
			extra += "- " + database + "\n";
			url = "/database/" + database;
			req = http_get_req( port: port, url: url, accept_header: "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8" );
			res = http_keepalive_send_recv( port: port, data: req );
			if(ContainsString( res, "\"code\": 401" ) && ContainsString( res, "\"reason\": \"Unauthorized\"" ) && ContainsString( res, "\"content\": \"401 Unauthorized.\"" )){
				set_kb_item( name: "www/" + host + "/" + port + "/content/auth_required", value: url );
				set_kb_item( name: "www/content/auth_required", value: TRUE );
				set_kb_item( name: "www/" + host + "/" + port + "/OrientDB/auth_required", value: url );
				set_kb_item( name: "OrientDB/auth_required", value: TRUE );
			}
		}
	}
	set_kb_item( name: "OrientDB/Installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:orientdb:orientdb:" );
	if(!cpe){
		cpe = "cpe:/a:orientdb:orientdb";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "OrientDB Server", version: version, install: "/", cpe: cpe, concluded: vers[0], concludedUrl: concUrl, extra: extra ), port: port );
	exit( 0 );
}

