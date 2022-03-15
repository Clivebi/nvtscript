if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108015" );
	script_version( "2021-03-19T10:51:02+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 10:51:02 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-11-08 11:37:33 +0100 (Tue, 08 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "libupnp Detection (UPnP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_upnp_detect.sc" );
	script_require_udp_ports( "Services/udp/upnp", 1900 );
	script_mandatory_keys( "upnp/identified" );
	script_tag( name: "summary", value: "UPnP based detection of libupnp." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 1900, proto: "upnp", ipproto: "udp" );
server = get_kb_item( "upnp/" + port + "/server" );
if(server && ContainsString( tolower( server ), "sdk for upnp" )){
	server = chomp( server );
	version = "unknown";
	vers = eregmatch( pattern: "(Portable|Intel|WindRiver) SDK for UPnP devices\\s*/([0-9.]+)", string: server, icase: TRUE );
	if(!isnull( vers[2] )){
		version = vers[2];
	}
	set_kb_item( name: "libupnp/detected", value: TRUE );
	set_kb_item( name: "libupnp/upnp/detected", value: TRUE );
	set_kb_item( name: "libupnp/upnp/port", value: port );
	set_kb_item( name: "libupnp/upnp/" + port + "/version", value: version );
	set_kb_item( name: "libupnp/upnp/" + port + "/concluded", value: server );
}
exit( 0 );

