if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108757" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-04-24 08:17:45 +0000 (Fri, 24 Apr 2020)" );
	script_name( "Huawei VRP Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/huawei/vrp/detected" );
	script_tag( name: "summary", value: "This script performs an Telnet banner based detection of Huawei Versatile Routing Platform (VRP) network devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "Warning: Telnet is not a secure protocol, and it is recommended to use Stelnet." )){
	exit( 0 );
}
model = "unknown";
version = "unknown";
patch_version = "unknown";
set_kb_item( name: "huawei/vrp/detected", value: TRUE );
set_kb_item( name: "huawei/vrp/telnet/port", value: port );
set_kb_item( name: "huawei/vrp/telnet/" + port + "/concluded", value: banner );
set_kb_item( name: "huawei/vrp/telnet/" + port + "/version", value: version );
set_kb_item( name: "huawei/vrp/telnet/" + port + "/model", value: model );
set_kb_item( name: "huawei/vrp/telnet/" + port + "/patch", value: patch_version );
exit( 0 );

