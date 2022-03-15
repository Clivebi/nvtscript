if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808250" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-07-14 16:30:56 +0530 (Thu, 14 Jul 2016)" );
	script_name( "HPE / Micro Focus Universal CMDB Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of HPE / Micro Focus Universal CMDB.

  This script sends an HTTP GET request and tries to get the version from the response." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://software.microfocus.com/en-us/products/configuration-management-system-database/overview" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
ucmdbPort = http_get_port( default: 8080 );
rcvRes = http_get_cache( item: "/ucmdb-ui/login_page.jsp", port: ucmdbPort );
if(IsMatchRegexp( rcvRes, "<title>(HP(E)? )?Universal CMDB</title>" ) && ContainsString( rcvRes, "STATE_LOGIN_FAILS" ) && ContainsString( rcvRes, "User Login:" )){
	version = "unknown";
	ver = eregmatch( pattern: "class=\"version\">(HP(E)? )?Universal CMDB ([0-9.]+)", string: rcvRes );
	if(!isnull( ver[3] )){
		version = ver[3];
	}
	set_kb_item( name: "HP/UCMDB/Installed", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:hp:universal_cmbd_foundation:" );
	if(!cpe){
		cpe = "cpe:/a:hp:universal_cmbd_foundation";
	}
	register_product( cpe: cpe, location: "/", port: ucmdbPort, service: "www" );
	log_message( data: build_detection_report( app: "HP / Micro Focus Universal CMDB", version: version, install: "/", cpe: cpe, concluded: ver[0] ), port: ucmdbPort );
	exit( 0 );
}
exit( 0 );

