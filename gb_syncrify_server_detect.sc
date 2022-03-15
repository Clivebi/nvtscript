if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805550" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-05-11 18:53:08 +0530 (Mon, 11 May 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Syncrify Server Remote Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of
  Syncrify Server.

  This script sends an HTTP GET request and tries to get the version from the
  response." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 5800 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("cpe.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
serPort = http_get_port( default: 5800 );
rcvRes = http_get_cache( item: "/app", port: serPort );
if(rcvRes && IsMatchRegexp( rcvRes, ">Powered by.*>Syncrify" )){
	Version = eregmatch( pattern: "Syncrify.*Version..([0-9.]+).-.build.([0-9.]+)", string: rcvRes );
	if(Version[1]){
		serVer = Version[1];
		set_kb_item( name: "syncrify/" + serPort + "/version", value: serVer );
		set_kb_item( name: "syncrify/installed", value: TRUE );
		buildVer = Version[2];
		if(buildVer){
			set_kb_item( name: "syncrify/" + serPort + "/build", value: buildVer );
		}
		cpe = build_cpe( value: serVer, exp: "^([0-9.]+)", base: "cpe:/a:syncrify:server:" );
		if(isnull( cpe )){
			cpe = "cpe:/a:syncrify:server";
		}
		register_product( cpe: cpe, location: "/", port: serPort, service: "www" );
		log_message( data: build_detection_report( app: "Syncrify Server", version: serVer + " Build: " + buildVer, install: "/", cpe: cpe, concluded: Version[0] ), port: serPort );
	}
}

