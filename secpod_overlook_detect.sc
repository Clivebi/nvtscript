if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902513" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-05-09 15:38:03 +0200 (Mon, 09 May 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "OPEN IT OverLook Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "webmirror.sc", "DDI_Directory_Scanner.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "The script sends an HTTP GET request to figure out whether OverLook is running on the remote host, and, if so, which version is installed." );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 80 );
if(!http_can_host_php( port: port )){
	exit( 0 );
}
for dir in make_list( "/overlook" ) {
	install = dir;
	if(dir == "/"){
		dir = "";
	}
	sndReq = http_get( item: NASLString( dir, "/src/login.php" ), port: port );
	rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
	if(ContainsString( rcvRes, ">OverLook by Open IT<" )){
		set_kb_item( name: "overlook/detected", value: TRUE );
		version = "unknown";
		version_url = dir + "/README";
		sndReq = http_get( item: version_url, port: port );
		rcvRes = http_keepalive_send_recv( port: port, data: sndReq );
		ver_match = eregmatch( pattern: "Version \\.+ ([0-9.]+)", string: rcvRes );
		if(ver_match[1]){
			version = ver_match[1];
			concluded_url = http_report_vuln_url( port: port, url: version_url, url_only: TRUE );
		}
		register_and_report_cpe( app: "OverLook", ver: version, concluded: ver_match[0], base: "cpe:/a:openit:overlook:", expr: "^([0-9.]+)", insloc: install, regPort: port, conclUrl: concluded_url );
		exit( 0 );
	}
}

