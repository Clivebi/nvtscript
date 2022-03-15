if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141536" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-09-28 14:16:14 +0700 (Fri, 28 Sep 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "IBM DataPower Gateway Detection" );
	script_tag( name: "summary", value: "Detection of IBM DataPower Gateway.

The script sends a connection request to the server and attempts to detect IBM DataPower Gateway and to extract
its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://www.ibm.com/products/datapower-gateway" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 443 );
res = http_get_cache( port: port, item: "/dp/login.xml" );
if(ContainsString( res, "login.startup(domainList" ) && ContainsString( res, "class=\"oneui\"" )){
	version = "unknown";
	prefix = eregmatch( pattern: "login.startup\\(domainList,\"([^\"]+)\"", string: res );
	if(!isnull( prefix[1] )){
		vers = eregmatch( pattern: prefix[1] + "\\.([0-9.]+)", string: res );
		if(!isnull( vers[1] )){
			version = vers[1];
		}
	}
	set_kb_item( name: "ibm_datapower_gateway/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:ibm:datapower_gateway:" );
	if(!cpe){
		cpe = "cpe:/a:ibm:datapower_gateway";
	}
	register_product( cpe: cpe, location: "/dp", port: port, service: "www" );
	log_message( data: build_detection_report( app: "IBM DataPower Gateway", version: version, install: "/dp", cpe: cpe, concluded: vers[0] ), port: port );
	exit( 0 );
}
exit( 0 );

