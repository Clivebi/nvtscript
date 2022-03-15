if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140765" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-12 16:06:34 +0700 (Mon, 12 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Brocade Fabric OS Detection (Telnet)" );
	script_tag( name: "summary", value: "Detection of Brocade Fabric OS.

  The script sends a telnet connection request to the device and attempts to detect the presence of devices running
  Fabric OS and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/brocade/fabric_os/detected" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "Fabric OS" )){
	version = "unknown";
	set_kb_item( name: "brocade_fabricos/detected", value: TRUE );
	set_kb_item( name: "brocade_fabricos/telnet/detected", value: TRUE );
	set_kb_item( name: "brocade_fabricos/telnet/port", value: port );
	vers = eregmatch( pattern: "(Fabos Version |Fabric OS.*Release v)([0-9a-z.]+)", string: banner );
	if(!isnull( vers[2] )){
		version = vers[2];
	}
	set_kb_item( name: "brocade_fabricos/telnet/" + port + "/concluded", value: banner );
	set_kb_item( name: "brocade_fabricos/telnet/" + port + "/version", value: version );
}
exit( 0 );

