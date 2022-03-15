if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103594" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-10-26 11:15:41 +0200 (Fri, 26 Oct 2012)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Grandstream GXP IP Phones Detection (HTTP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "find_service.sc", "httpver.sc", "global_settings.sc" );
	script_require_ports( "Services/www", 80 );
	script_exclude_keys( "Settings/disable_cgi_scanning" );
	script_tag( name: "summary", value: "Detection of Grandstream GXP IP Phones.

  This script performs a HTTP based detection of Grandstream GXP IP Phones." );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
banner = http_get_remote_headers( port: port, file: "/cgi-bin/login" );
if(!banner || !ContainsString( banner, "Server: Grandstream GXP" )){
	exit( 0 );
}
set_kb_item( name: "grandstream/gxp/detected", value: TRUE );
set_kb_item( name: "grandstream/gxp/http/port", value: port );
model = "unknown";
version = "unknown";
vers = eregmatch( pattern: "Server: Grandstream (GXP[^\\r\\n ]+)( ([0-9.]+))?", string: banner );
if(!isnull( vers[1] )){
	model = vers[1];
	set_kb_item( name: "grandstream/gxp/http/" + port + "/concluded", value: vers[0] );
}
if(!isnull( vers[3] )){
	version = vers[3];
}
set_kb_item( name: "grandstream/gxp/http/" + port + "/model", value: model );
set_kb_item( name: "grandstream/gxp/http/" + port + "/version", value: version );
exit( 0 );

