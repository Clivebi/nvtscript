if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141800" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-12-20 11:33:24 +0700 (Thu, 20 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ABB M2M ETHERNET Detection" );
	script_tag( name: "summary", value: "Detection of ABB M2M ETHERNET .

The script sends a connection request to the server and attempts to detect ABB M2M ETHERNET and to extract its
version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 8080 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_xref( name: "URL", value: "https://new.abb.com/" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 8080 );
res = http_get_cache( port: port, item: "/" );
if(ContainsString( res, "<title>M2M Ethernet</title>" ) && ContainsString( res, "/protect/auth.htm" )){
	version = "unknown";
	vers = eregmatch( pattern: "FW ver\\. ([0-9.]+)", string: res );
	if(!isnull( vers[1] )){
		version = vers[1];
	}
	eth_vers = eregmatch( pattern: "ETH-FW ver\\. ([0-9.]+)", string: res );
	if(!isnull( eth_vers[1] )){
		extra = "ETH-FW version:    " + eth_vers[1];
		set_kb_item( name: "abb_m2m_ethernet/eth_fw_version", value: eth_vers[1] );
	}
	set_kb_item( name: "abb_m2m_ethernet/detected", value: TRUE );
	cpe = build_cpe( value: version, exp: "^([0-9.]+)", base: "cpe:/a:abb:m2m_ethernet_firmware:" );
	if(!cpe){
		cpe = "cpe:/a:abb:m2m_ethernet_firmware";
	}
	register_product( cpe: cpe, location: "/", port: port, service: "www" );
	log_message( data: build_detection_report( app: "ABB M2M ETHERNET", version: version, install: "/", cpe: cpe, concluded: vers[0], extra: extra ), port: port );
	exit( 0 );
}
exit( 0 );

