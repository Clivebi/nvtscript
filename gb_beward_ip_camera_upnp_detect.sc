if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.114074" );
	script_version( "2021-02-25T16:05:56+0000" );
	script_tag( name: "last_modification", value: "2021-02-25 16:05:56 +0000 (Thu, 25 Feb 2021)" );
	script_tag( name: "creation_date", value: "2019-02-19 14:54:11 +0100 (Tue, 19 Feb 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Beward IP Camera Detection (UPnP)" );
	script_tag( name: "summary", value: "UPnP based detection of Beward IP cameras." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_upnp_detect.sc" );
	script_mandatory_keys( "upnp/identified" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 1900, ipproto: "udp", proto: "upnp" );
banner = get_kb_item( "upnp/" + port + "/banner" );
if(banner && egrep( pattern: "DEVICE-INFO:\\s*Beward", string: banner, icase: TRUE )){
	model = "unknown";
	version = "unknown";
	info = eregmatch( pattern: "DEVICE-INFO:\\s*Beward/([^/]+)/([^/]+)/", string: banner );
	if(info){
		if(!isnull( info[1] )){
			model = info[1];
		}
		if(!isnull( info[2] )){
			version = info[2];
		}
		set_kb_item( name: "beward/ip_camera/upnp/" + port + "/concluded", value: info[0] );
	}
	set_kb_item( name: "beward/ip_camera/detected", value: TRUE );
	set_kb_item( name: "beward/ip_camera/upnp/detected", value: TRUE );
	set_kb_item( name: "beward/ip_camera/upnp/port", value: port );
	set_kb_item( name: "beward/ip_camera/upnp/" + port + "/model", value: model );
	set_kb_item( name: "beward/ip_camera/upnp/" + port + "/version", value: version );
}
exit( 0 );

