if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100328" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2009-10-30 14:42:19 +0100 (Fri, 30 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "LANDesk Management Agent Detection" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( 9595, 9593 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of LANDesk Management Agent" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
host = http_host_name( dont_add_port: TRUE );
for port in make_list( 9595,
	 9593 ) {
	if(!get_port_state( port )){
		continue;
	}
	if(http_get_is_marked_broken( port: port, host: host )){
		continue;
	}
	buf = http_get_cache( item: "/", port: port );
	if(isnull( buf )){
		continue;
	}
	if(concl = egrep( pattern: "LANDesk.*Management Agent</title>", string: buf, icase: TRUE )){
		install = "/";
		version = "unknown";
		set_kb_item( name: "landesk_managament_agent/detected", value: TRUE );
		cpe = "cpe:/a:landesk:landesk_management_suite";
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		service_register( port: port, ipproto: "tcp", proto: "landesk" );
		log_message( data: build_detection_report( app: "LANDesk Management Agent", version: version, install: "/", cpe: cpe, concluded: concl ), port: port );
	}
}
exit( 0 );

