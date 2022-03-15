if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106009" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-16 09:22:17 +0700 (Tue, 16 Jun 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "Bonita BPM Detection" );
	script_tag( name: "summary", value: "Detection of Bonita BPM.

  The script sends a connection request to the server and attempts to detect Bonita BPM." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 8080 );
for dir in nasl_make_list_unique( "/bonita", http_cgi_dirs( port: port ) ) {
	rep_dir = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.jsp";
	buf = http_get_cache( item: url, port: port );
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( buf, "Bonita BPM Portal" )){
		vers = NASLString( "unknown" );
		set_kb_item( name: "bonita_bpm/installed", value: TRUE );
		cpe = "cpe:/a:bonitasoft:bonita_bpm";
		register_product( cpe: cpe, location: rep_dir, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Bonita BPM", version: vers, install: rep_dir, cpe: cpe ), port: port );
	}
}
exit( 0 );

