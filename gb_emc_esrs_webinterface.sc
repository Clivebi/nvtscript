if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140137" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-07T06:04:54+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 06:04:54 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-31 15:41:36 +0100 (Tue, 31 Jan 2017)" );
	script_name( "EMC Secure Remote Services Webinterface Detection" );
	script_tag( name: "summary", value: "This script performs HTTP based detection of EMC Secure Remote Services Webinterface" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 9443 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
port = http_get_port( default: 9443 );
url = "/esrs/html/about.html";
req = http_get( item: url, port: port );
buf = http_keepalive_send_recv( port: port, data: req, bodyonly: FALSE );
if(ContainsString( buf, "<h2>About EMC Secure Remote Services" )){
	cpe = "cpe:/a:emc:secure_remote_services";
	register_product( cpe: cpe, location: "/esrs", port: port, service: "www" );
	log_message( port: port, data: "The EMC Secure Remote Services Webinterface is running at this port.\nCPE: " + cpe + "\n" );
	exit( 0 );
}
exit( 0 );

