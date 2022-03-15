if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100217" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2009-06-01 13:46:24 +0200 (Mon, 01 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "phpBugTracker Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This host is running phpBugTracker, a web-based bug tracker with
 functionality similar to other issue tracking systems, such as Bugzilla." );
	script_xref( name: "URL", value: "http://phpbt.sourceforge.net/" );
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
for dir in nasl_make_list_unique( "/phpbt", "/bugtracker", "/bugs", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	buf = http_get_cache( item: dir + "/index.php", port: port );
	if(( egrep( pattern: "<title>phpBugTracker - Home</title>", string: buf, icase: TRUE ) || egrep( pattern: "<title>Home - phpBugTracker</title>", string: buf, icase: TRUE ) ) && egrep( pattern: "bug.php\\?op=add", string: buf, icase: TRUE )){
		version = "unknown";
		req = http_get( item: dir + "/CHANGELOG", port: port );
		buf = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
		ver = eregmatch( string: buf, pattern: "-- ([0-9.]+)" );
		if(!isnull( ver[1] )){
			version = ver[1];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/phpBugTracker", value: tmp_version );
		set_kb_item( name: "phpBugTracker/installed", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+?)", base: "cpe:/a:benjamin_curtis:phpbugtracker:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:benjamin_curtis:phpbugtracker";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "phpBugTracker", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

