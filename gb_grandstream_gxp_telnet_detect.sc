if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143706" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-04-15 08:28:52 +0000 (Wed, 15 Apr 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Grandstream GXP IP Phones Detection (Telnet)" );
	script_tag( name: "summary", value: "Detection of Grandstream GXP IP Phones.

  This script performs Telnet based detection of Grandstream GXP IP Phones." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/grandstream/gxp/detected" );
	exit( 0 );
}
require("dump.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("telnet_func.inc.sc");
port = telnet_get_port( default: 23 );
if(!banner = telnet_get_banner( port: port )){
	exit( 0 );
}
if(ContainsString( banner, "Grandstream GXP" )){
	model = "unknown";
	version = "unknown";
	set_kb_item( name: "grandstream/gxp/detected", value: TRUE );
	set_kb_item( name: "grandstream/gxp/telnet/port", value: port );
	set_kb_item( name: "grandstream/gxp/telnet/" + port + "/concluded", value: banner );
	mod = eregmatch( pattern: "Grandstream (GXP[0-9]+)", string: banner );
	if(!isnull( mod[1] )){
		model = mod[1];
	}
	set_kb_item( name: "grandstream/gxp/telnet/" + port + "/model", value: model );
	set_kb_item( name: "grandstream/gxp/telnet/" + port + "/version", value: version );
}
exit( 0 );

