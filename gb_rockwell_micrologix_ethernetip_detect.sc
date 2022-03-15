require("plugin_feed_info.inc.sc");
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141771" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2018-12-12 12:47:16 +0700 (Wed, 12 Dec 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Rockwell Automation MicroLogix Detection (EtherNet/IP)" );
	script_tag( name: "summary", value: "Detection of Rockwell Automation MicroLogix PLC's.

  This script performs EtherNet/IP based detection of Rockwell Automation MicroLogix PLC's." );
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
vendor = get_kb_item( "ethernetip/" + port + "/" + proto + "/vendor" );
if(!vendor || !IsMatchRegexp( vendor, "^Rockwell Automation" )){
	exit( 0 );
}
prod_name = get_kb_item( "ethernetip/" + port + "/" + proto + "/product_name" );
if(!prod_name || !IsMatchRegexp( prod_name, "^17" )){
	exit( 0 );
}
set_kb_item( name: "rockwell_micrologix/detected", value: TRUE );
set_kb_item( name: "rockwell_micrologix/ethernetip/detected", value: TRUE );
set_kb_item( name: "rockwell_micrologix/ethernetip/port", value: port );
set_kb_item( name: "rockwell_micrologix/ethernetip/proto", value: proto );
set_kb_item( name: "rockwell_micrologix/ethernetip/" + port + "/proto", value: proto );
mod = eregmatch( pattern: "([^/ ]+)", string: prod_name );
if(!isnull( mod[1] )){
	set_kb_item( name: "rockwell_micrologix/ethernetip/" + port + "/" + proto + "/model", value: mod[1] );
}
buf = eregmatch( pattern: "([^ ]+) ([A-Z])/([0-9.]+)", string: prod_name );
if(!isnull( buf[2] )){
	set_kb_item( name: "rockwell_micrologix/ethernetip/" + port + "/" + proto + "/series", value: buf[2] );
}
if(!isnull( buf[3] )){
	set_kb_item( name: "rockwell_micrologix/ethernetip/" + port + "/" + proto + "/fw_version", value: buf[3] );
}
exit( 0 );

