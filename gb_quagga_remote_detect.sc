if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105551" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "$Revision: 11885 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 15:47:20 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2016-02-16 16:56:28 +0100 (Tue, 16 Feb 2016)" );
	script_name( "Quagga Detection" );
	script_tag( name: "summary", value: "The script sends a connection request to the server and attempts to extract the version number from the reply." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "find_service2.sc" );
	script_require_ports( "Services/quagga", 2602 );
	exit( 0 );
}
require("host_details.inc.sc");
port = get_kb_item( "Services/quagga" );
if(!port){
	port = 2602;
}
if(!get_port_state( port )){
	exit( 0 );
}
banner = get_kb_item( "FindService/tcp/" + port + "/help" );
if(!ContainsString( tolower( banner ), "hello, this is quagga" )){
	exit( 0 );
}
set_kb_item( name: "quagga/installed", value: TRUE );
cpe = "cpe:/a:quagga:quagga";
vers = "unknown";
version = eregmatch( pattern: "Hello, this is [qQ]uagga \\(version ([^)]+)\\)", string: banner );
if(!isnull( version[1] )){
	vers = version[1];
	cpe += ":" + vers;
}
register_product( cpe: cpe, location: port + "/tcp", port: port );
log_message( port: port, data: build_detection_report( app: "Quagga", version: vers, install: port + "/tcp", cpe: cpe, concluded: "telnet banner" ) );
exit( 0 );

