if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800180" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-09 08:34:53 +0200 (Wed, 09 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Pacific Timesheet Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "no404.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80, 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "This script is detects the installed version of Pacific Timesheet." );
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
for dir in nasl_make_list_unique( "/", "/timesheet", http_cgi_dirs( port: port ) ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: dir + "/about-show.do", port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	if(IsMatchRegexp( rcvRes, "^HTTP/1\\.[01] 200" ) && ContainsString( rcvRes, ">About Pacific Timesheet<" )){
		version = "unknown";
		ver = eregmatch( pattern: ">Version ([0-9.]+) [Bb][Uu][Ii][Ll][Dd]" + " ([0-9]+)</", string: rcvRes );
		if(ver[1] != NULL && ver[2] != NULL){
			version = ver[1] + "." + ver[2];
		}
		tmp_version = version + " under " + install;
		set_kb_item( name: "www/" + port + "/pacificTimeSheet/Ver", value: tmp_version );
		set_kb_item( name: "pacifictimesheet/detected", value: TRUE );
		cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:pacifictimesheet:pacific_timesheet:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:pacifictimesheet:pacific_timesheet";
		}
		register_product( cpe: cpe, location: install, port: port, service: "www" );
		log_message( data: build_detection_report( app: "Pacific Timesheet", version: version, install: install, cpe: cpe, concluded: ver[0] ), port: port );
	}
}
exit( 0 );

