if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105131" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-12-03 13:24:33 +0100 (Wed, 03 Dec 2014)" );
	script_name( "IBM Endpoint Manager MDM Installed" );
	script_tag( name: "summary", value: "The script sends a connection
request to the server and attempts to detect if Mobile Device Management
component is installed." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_ibm_endpoint_manager_web_detect.sc" );
	script_require_ports( "Services/www", 443 );
	script_mandatory_keys( "ibm_endpoint_manager/installed" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 443 );
buf = http_get_cache( item: "/", port: port );
if(ContainsString( buf, ">Mobile Device Enrollment<" ) && ContainsString( buf, "_mdm_session=" ) && ContainsString( buf, "Server: Jetty" )){
	set_kb_item( name: "ibm_endpoint_manager/MDM", value: TRUE );
	log_message( port: port, data: "IBM Endpoint Manager Mobile Device Management is running at this port" );
	exit( 0 );
}
exit( 0 );

