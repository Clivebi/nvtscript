if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108754" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-04-22 08:48:02 +0000 (Wed, 22 Apr 2020)" );
	script_name( "Huawei VRP Detection (SSH-Banner)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "ssh_detect.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/huawei/vrp/detected" );
	script_tag( name: "summary", value: "This script performs an SSH banner based detection of Huawei Versatile Routing Platform (VRP) network devices." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ssh_get_port( default: 22 );
banner = ssh_get_serverbanner( port: port );
if(!banner || !ContainsString( banner, "SSH-2.0-HUAWEI-" )){
	exit( 0 );
}
model = "unknown";
version = "unknown";
patch_version = "unknown";
set_kb_item( name: "huawei/vrp/detected", value: TRUE );
set_kb_item( name: "huawei/vrp/ssh-banner/port", value: port );
set_kb_item( name: "huawei/vrp/ssh-banner/" + port + "/concluded", value: banner );
set_kb_item( name: "huawei/vrp/ssh-banner/" + port + "/version", value: version );
set_kb_item( name: "huawei/vrp/ssh-banner/" + port + "/model", value: model );
set_kb_item( name: "huawei/vrp/ssh-banner/" + port + "/patch", value: patch_version );
exit( 0 );

