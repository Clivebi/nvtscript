if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141141" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-06-06 08:31:40 +0700 (Wed, 06 Jun 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Huawei iBMC Detection (UPnP)" );
	script_tag( name: "summary", value: "UPnP based detection of Huawei iBMC over UPnP." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_upnp_detect.sc" );
	script_require_udp_ports( "Services/udp/upnp", 1900 );
	script_mandatory_keys( "upnp/identified" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 1900, ipproto: "udp", proto: "upnp" );
if(!banner = get_kb_item( "upnp/" + port + "/banner" )){
	exit( 0 );
}
if(!ContainsString( banner, " iBMC/" )){
	exit( 0 );
}
version = "unknown";
model = "unknown";
set_kb_item( name: "huawei/ibmc/detected", value: TRUE );
set_kb_item( name: "huawei/data_communication_product/detected", value: TRUE );
set_kb_item( name: "huawei/ibmc/upnp/port", value: port );
set_kb_item( name: "huawei/ibmc/upnp/" + port + "/concluded", value: egrep( pattern: " iBMC", string: banner ) );
vers = eregmatch( pattern: "iBMC/([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
}
mod = eregmatch( pattern: "ProductName/([^SN/]+)", string: banner );
if(!isnull( mod[1] )){
	model = chomp( mod[1] );
}
set_kb_item( name: "huawei/ibmc/upnp/" + port + "/version", value: version );
set_kb_item( name: "huawei/ibmc/upnp/" + port + "/model", value: model );
exit( 0 );

