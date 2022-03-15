if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105404" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2015-10-15 11:45:06 +0200 (Thu, 15 Oct 2015)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "ZHONE ZNID GPON Device Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/zhone/znid_gpon/detected" );
	script_tag( name: "summary", value: "Telnet based detection of ZHONE ZNID GPON devices" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "Model: ZNID-GPON" )){
	exit( 0 );
}
model = "unknown";
version = "unknown";
set_kb_item( name: "dasanzhone/znid/detected", value: TRUE );
set_kb_item( name: "dasanzhone/znid/telnet/port", value: port );
mod = eregmatch( pattern: "Model: ZNID-GPON-([^- ]+)[^\r\n]+", string: banner );
if(!isnull( mod[1] )){
	model = mod[1];
	concluded = "\n    " + mod[0];
}
vers = eregmatch( pattern: "Release: S([0-9.]+)", string: banner );
if(!isnull( vers[1] )){
	version = vers[1];
	concluded += "\n    " + vers[0];
}
if(concluded){
	set_kb_item( name: "dasanzhone/znid/telnet/" + port + "/concluded", value: concluded );
}
set_kb_item( name: "dasanzhone/znid/telnet/" + port + "/model", value: model );
set_kb_item( name: "dasanzhone/znid/telnet/" + port + "/version", value: version );
exit( 0 );

