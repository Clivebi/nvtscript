if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113224" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-07-06 10:41:45 +0200 (Fri, 06 Jul 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Ecessa ShieldLink/PowerLink Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/ecessa/shield_power_link/detected" );
	script_tag( name: "summary", value: "Checks if the target is an Ecessa ShieldLink
  or PowerLink device, and, if so, retrieves the version using Telnet." );
	script_xref( name: "URL", value: "https://www.ecessa.com/powerlink/" );
	script_xref( name: "URL", value: "https://www.ecessa.com/powerlink/product_comp_shieldlink/" );
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
if( IsMatchRegexp( banner, "ShieldLink" ) ){
	kb_base = "ecessa_shieldlink";
}
else {
	if( IsMatchRegexp( banner, "PowerLink" ) ){
		kb_base = "ecessa_powerlink";
	}
	else {
		exit( 0 );
	}
}
set_kb_item( name: "ecessa_link/detected", value: TRUE );
set_kb_item( name: kb_base + "/detected", value: TRUE );
set_kb_item( name: kb_base + "/telnet/port", value: port );
set_kb_item( name: kb_base + "/telnet/concluded", value: banner );
version = "unknown";
vers = eregmatch( string: banner, pattern: "Version ([0-9.]+)" );
if(!isnull( vers[1] )){
	version = vers[1];
}
set_kb_item( name: kb_base + "/telnet/version", value: version );
exit( 0 );

