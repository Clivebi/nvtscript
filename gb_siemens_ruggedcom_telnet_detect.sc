if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140808" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-26 11:52:48 +0700 (Mon, 26 Feb 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Siemens RUGGEDCOM / Rugged Operating System Detection (Telnet)" );
	script_tag( name: "summary", value: "Detection of Siemens RUGGEDCOM devices and the Rugged Operating System.

The script sends a telnet connection request to the device and attempts to detect the presence of devices running
RUGGEDCOM / Rugged Operating System and to extract its version." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/siemens/ruggedcom/detected" );
	exit( 0 );
}
require("host_details.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "Rugged Operating System" ) || ContainsString( banner, "Command Line Interface RUGGEDCOM" )){
	version = "unknown";
	set_kb_item( name: "siemens_ruggedcom/detected", value: TRUE );
	set_kb_item( name: "siemens_ruggedcom/telnet/detected", value: TRUE );
	set_kb_item( name: "siemens_ruggedcom/telnet/port", value: port );
	vers = eregmatch( pattern: "Rugged Operating System v([0-9.]+)", string: banner );
	if(!isnull( vers[1] )){
		set_kb_item( name: "siemens_ruggedcom/telnet/" + port + "/version", value: vers[1] );
		set_kb_item( name: "siemens_ruggedcom/telnet/" + port + "/concluded", value: vers[0] );
	}
	prod = eregmatch( pattern: "Product: *([^\n\r]+)", string: banner );
	if( !isnull( prod[1] ) ) {
		set_kb_item( name: "siemens_ruggedcom/telnet/" + port + "/model", value: prod[1] );
	}
	else {
		prod = eregmatch( pattern: "Interface RUGGEDCOM ([^\r\n]+)", string: banner );
	}
	if(!isnull( prod[1] )){
		set_kb_item( name: "siemens_ruggedcom/telnet/" + port + "/model", value: prod[1] );
	}
	mac = eregmatch( pattern: "MAC Address: *([A-F0-9-]{17})", string: banner );
	if(!isnull( mac[1] )){
		mac = str_replace( string: mac[1], find: "-", replace: ":" );
		register_host_detail( name: "MAC", value: tolower( mac ), desc: "Siemens RUGGEDCOM Detection (Telnet)" );
		replace_kb_item( name: "Host/mac_address", value: tolower( mac ) );
		set_kb_item( name: "siemens_ruggedcom/telnet/" + port + "/mac", value: tolower( mac ) );
	}
}
exit( 0 );

