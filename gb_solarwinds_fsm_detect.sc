if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106013" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-06-30 10:54:34 +0700 (Tue, 30 Jun 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_active" );
	script_name( "Solarwinds Firewall Security Manager Detection" );
	script_tag( name: "summary", value: "Detection of Solarwinds Firewall Security Manager

The script sends a connection request to the server and attempts to detect Solarwinds Firewall
Security Manager (FSM)." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 48080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 48080 );
for dir in nasl_make_list_unique( "/fsm", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/login.jsp";
	buf = http_get_cache( item: url, port: port );
	if(buf == NULL){
		continue;
	}
	if(IsMatchRegexp( buf, "^HTTP/1\\.[01] 200" ) && IsMatchRegexp( buf, "SolarWinds FSM Change Advisor" )){
		vers = NASLString( "unknown" );
		set_kb_item( name: "solarwinds_fsm/installed", value: TRUE );
		cpe = "cpe:/a:solarwinds:firewall_security_manager";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Solarwinds Firewall Security Manager", version: vers, install: install, cpe: cpe ), port: port );
	}
}
exit( 0 );

