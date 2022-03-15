require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141768" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-12-07 13:39:37 +0700 (Fri, 07 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "WAGO PLC Detection (EtherNet/IP)" );
	script_tag( name: "summary", value: "This script performs EtherNet/IP based detection of WAGO PLC Controllers." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_ethernetip_tcp_detect.sc" );
	if(FEED_NAME == "GSF" || FEED_NAME == "SCM"){
		script_dependencies( "gsf/gb_ethernetip_udp_detect.sc" );
	}
	script_mandatory_keys( "ethernetip/detected" );
	exit( 0 );
}
require("port_service_func.inc.sc");
if(!proto = get_kb_item( "ethernetip/proto" )){
	exit( 0 );
}
port = service_get_port( default: 44818, proto: "ethernetip", ipproto: proto );
prod_name = get_kb_item( "ethernetip/" + port + "/" + proto + "/product_name" );
if(!prod_name || !IsMatchRegexp( prod_name, "^WAGO 750-" )){
	exit( 0 );
}
set_kb_item( name: "wago_plc/detected", value: TRUE );
set_kb_item( name: "wago_plc/ethernetip/detected", value: TRUE );
set_kb_item( name: "wago_plc/ethernetip/port", value: port );
set_kb_item( name: "wago_plc/ethernetip/proto", value: proto );
set_kb_item( name: "wago_plc/ethernetip/" + port + "/proto", value: proto );
mod = eregmatch( pattern: "WAGO (.*)", string: prod_name );
if(!isnull( mod[1] )){
	set_kb_item( name: "wago_plc/ethernetip/" + port + "/" + proto + "/model", value: mod[1] );
}
if(rev = get_kb_item( "ethernetip/" + port + "/" + proto + "/revision" )){
	set_kb_item( name: "wago_plc/ethernetip/" + port + "/" + proto + "/fw_version", value: rev );
}
exit( 0 );

