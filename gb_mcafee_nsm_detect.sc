if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140948" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-04-05 10:54:07 +0700 (Thu, 05 Apr 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "McAfee Network Security Manager(NSM)Detection" );
	script_tag( name: "summary", value: "Detection of McAfee NSM.

The script sends a connection request to the server and attempts to detect McAfee Network Security Manager and to
extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.mcafee.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/intruvert/jsp/module/Login.jsp" );
if(ContainsString( res, "Network Security Manager" ) && ContainsString( res, "alt=\"Dashboard\" title=\"Dashboard\">" )){
	version = "unknown";
	vers = eregmatch( pattern: "/intruvert/([0-9.]+)/", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	set_kb_item( name: "mcafee_nsm/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:mcafee:network_security_manager:" );
	if(!cpe){
		cpe = "cpe:/a:mcafee:network_security_manager";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "McAfee Network Security Manager", version: version, install: "/", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

