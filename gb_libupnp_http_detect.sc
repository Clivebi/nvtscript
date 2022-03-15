if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106376" );
	script_version( "2021-03-19T10:51:02+0000" );
	script_tag( name: "last_modification", value: "2021-03-19 10:51:02 +0000 (Fri, 19 Mar 2021)" );
	script_tag( name: "creation_date", value: "2016-11-04 14:37:33 +0700 (Fri, 04 Nov 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "libupnp Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gb_get_http_banner.sc" );
	script_require_ports( "Services/www", 49152 );
	script_mandatory_keys( "sdk_for_upnp/banner" );
	script_tag( name: "summary", value: "HTTP based detection of libupnp." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 49152 );
banner = http_get_remote_headers( port: port );
if(banner && concl = egrep( string: banner, pattern: "Server\\s*:.+SDK for UPnP", icase: TRUE )){
	concl = chomp( concl );
	version = "unknown";
	vers = eregmatch( pattern: "(Portable|Intel|WindRiver) SDK for UPnP devices\\s*/([0-9.]+)", string: banner, icase: TRUE );
	if(!isnull( vers[2] )){
		version = vers[2];
	}
	set_kb_item( name: "libupnp/detected", value: TRUE );
	set_kb_item( name: "libupnp/http/detected", value: TRUE );
	set_kb_item( name: "libupnp/http/port", value: port );
	set_kb_item( name: "libupnp/http/" + port + "/version", value: version );
	set_kb_item( name: "libupnp/http/" + port + "/concluded", value: concl );
}
exit( 0 );

