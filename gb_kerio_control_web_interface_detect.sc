if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140067" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-11-17 12:32:06 +0100 (Thu, 17 Nov 2016)" );
	script_name( "Kerio Control Web Interface Detection" );
	script_tag( name: "summary", value: "The script performs HTTP based detection of the Kerio Control Web Interface" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 4081 );
	script_mandatory_keys( "KCEWS/banner" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 4081 );
banner = http_get_remote_headers( port: port );
if(!ContainsString( banner, "Server: Kerio Control Embedded Web Server" )){
	exit( 0 );
}
set_kb_item( name: "kerio/control/webiface", value: TRUE );
cpe = "cpe:/a:kerio:control";
register_product( cpe: cpe, location: "/", port: port, service: "www" );
log_message( port: port, data: "The Kerio Connect Web Interface is running at this port\nCPE: " + cpe + "\n" );
exit( 0 );

