if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108312" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-11 09:03:31 +0100 (Mon, 11 Dec 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Hirschmann Devices Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/hirschmann/device/detected" );
	script_tag( name: "summary", value: "This script performs Telnet based detection of Hirschmann Devices." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
require("telnet_func.inc.sc");
require("host_details.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "Hirschmann Automation and Control GmbH" )){
	set_kb_item( name: "hirschmann_device/detected", value: TRUE );
	set_kb_item( name: "hirschmann_device/telnet/detected", value: TRUE );
	set_kb_item( name: "hirschmann_device/telnet/port", value: port );
	fw_version = "unknown";
	product_name = "unknown";
	platform_name = "unknown";
	rls_banner = egrep( pattern: " Release ", string: banner );
	if( rls_banner ){
		rls_banner = ereg_replace( pattern: "^(\\s+)", replace: "", string: rls_banner );
		rls_banner = chomp( rls_banner );
		vers_prod_nd_model = eregmatch( pattern: "([^\\r\\n]+) Release ([0-9a-zA-Z]+)-([0-9a-zA-Z]+-)?([0-9.]+)", string: rls_banner );
		if( vers_prod_nd_model ){
			product_name = vers_prod_nd_model[1];
			fw_version = vers_prod_nd_model[4];
			if( vers_prod_nd_model[3] ){
				platform_name = vers_prod_nd_model[2] + "-";
				platform_name += ereg_replace( pattern: "-$", string: vers_prod_nd_model[3], replace: "" );
			}
			else {
				platform_name = vers_prod_nd_model[2];
			}
			set_kb_item( name: "hirschmann_device/telnet/" + port + "/concluded", value: vers_prod_nd_model[0] );
		}
		else {
			set_kb_item( name: "hirschmann_device/telnet/" + port + "/concluded", value: bin2string( ddata: rls_banner, noprint_replacement: "" ) );
		}
	}
	else {
		set_kb_item( name: "hirschmann_device/telnet/" + port + "/concluded", value: bin2string( ddata: banner, noprint_replacement: "" ) );
	}
	set_kb_item( name: "hirschmann_device/telnet/" + port + "/fw_version", value: fw_version );
	set_kb_item( name: "hirschmann_device/telnet/" + port + "/product_name", value: product_name );
	set_kb_item( name: "hirschmann_device/telnet/" + port + "/platform_name", value: platform_name );
	if(mac = eregmatch( pattern: "Base-MAC[ ]+:[ ]+([0-9a-fA-F:]{17})", string: banner )){
		register_host_detail( name: "MAC", value: mac[1], desc: "Get the MAC Address via Hirschmann Telnet banner" );
		replace_kb_item( name: "Host/mac_address", value: mac[1] );
	}
}
exit( 0 );

