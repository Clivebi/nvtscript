if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106243" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-09-14 13:50:44 +0700 (Wed, 14 Sep 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Opmantek NMIS Detection" );
	script_tag( name: "summary", value: "Detection of Opmantek NMIS

The script attempts to identify Opmantek NMIS and to extract the version number." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://opmantek.com/network-management-system-nmis/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
port = http_get_port( default: 80 );
for dir in nasl_make_list_unique( "/cgi-nmis8", "/cgi-nmis4", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	url = dir + "/nmiscgi.pl";
	req = http_get( port: port, item: url );
	res = http_keepalive_send_recv( port: port, data: req );
	if(ContainsString( res, "Network Management Information System" ) && ContainsString( res, "www.opmantek.com" )){
		version = "unknown";
		ver = eregmatch( pattern: "NMIS ([0-9.]+([A-Z])?)", string: res );
		if(!isnull( ver[1] )){
			version = ver[1];
			set_kb_item( name: "opmantek_nmis/version", value: version );
		}
		set_kb_item( name: "opmantek_nmis/installed", value: TRUE );
		cpe = build_cpe( value: tolower( version ), exp: "^([0-9a-z.]+)", base: "cpe:/a:opmantek:nmis:" );
		if(!cpe){
			cpe = "cpe:/a:opmantek:nmis";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Opmantek NMIS", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
		exit( 0 );
	}
}
exit( 0 );

