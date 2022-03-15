if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108302" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-11-29 08:03:31 +0100 (Wed, 29 Nov 2017)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Lantronix Devices Detection (Telnet)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23, 9999 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "summary", value: "This script performs Telnet based detection of Lantronix Devices." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
require("telnet_func.inc.sc");
require("host_details.inc.sc");
port = telnet_get_port( default: 9999 );
banner = telnet_get_banner( port: port );
if(egrep( string: banner, pattern: "^Lantronix .* Version ", icase: FALSE ) || ( ( !IsMatchRegexp( banner, "(IQinVision|IQEye) " ) ) && IsMatchRegexp( banner, "Type HELP at the .* prompt for assistance" ) ) || ( ContainsString( banner, "Lantronix" ) && ( ContainsString( banner, "Password :" ) || ( ContainsString( banner, "Press Enter" ) && ContainsString( banner, "Setup Mode" ) ) ) ) || ( port == 9999 && ContainsString( banner, "Software version " ) && ContainsString( banner, "MAC address " ) )){
	set_kb_item( name: "lantronix_device/detected", value: TRUE );
	set_kb_item( name: "lantronix_device/telnet/detected", value: TRUE );
	set_kb_item( name: "lantronix_device/telnet/port", value: port );
	version = "unknown";
	vers = eregmatch( pattern: "(Software version|Version) [VB]?([0-9.]+)", string: banner );
	if( vers[2] ){
		version = vers[2];
		set_kb_item( name: "lantronix_device/telnet/" + port + "/concluded", value: vers[0] );
	}
	else {
		set_kb_item( name: "lantronix_device/telnet/" + port + "/concluded", value: bin2string( ddata: banner, noprint_replacement: "" ) );
	}
	set_kb_item( name: "lantronix_device/telnet/" + port + "/version", value: version );
	type = "unknown";
	if( !ContainsString( banner, "Lantronix" ) && ContainsString( banner, "Software version " ) && ContainsString( banner, "MAC address " ) ){
		type = "Branded";
	}
	else {
		if( ContainsString( banner, "Lantronix Inc. - Modbus Bridge" ) ){
			type = "Modbus Bridge";
		}
		else {
			if( ContainsString( banner, "Lantronix Universal Device Server" ) ){
				type = "UDS";
			}
			else {
				if( ContainsString( banner, "Lantronix Demo Server" ) ){
					type = "Demo Server";
				}
				else {
					if( ContainsString( banner, "Lantronix CoBox" ) ){
						type = "CoBox";
					}
					else {
						if( ContainsString( banner, "Sielox/Lantronix Network Adaptor" ) || ContainsString( banner, "Checkpoint/Lantronix Network Adaptor" ) ){
							type = "Branded";
						}
						else {
							if(_type = eregmatch( pattern: "Lantronix ([A-Z0-9-]+) ", string: banner )){
								type = _type[1];
							}
						}
					}
				}
			}
		}
	}
	if(type == "unknown"){
		username = "login";
		access = FALSE;
		soc = open_sock_tcp( port );
		if(soc){
			recv1 = recv( socket: soc, length: 2048, timeout: 10 );
			if(ContainsString( recv1, "prompt for assistance" ) && ContainsString( recv1, "Username>" )){
				send( socket: soc, data: username + "\r\n" );
				recv2 = recv( socket: soc, length: 2048, timeout: 10 );
				if(IsMatchRegexp( recv2, "Local_.+>" )){
					access = TRUE;
					set_kb_item( name: "lantronix_device/telnet/" + port + "/access", value: TRUE );
				}
			}
			if(access){
				send( socket: soc, data: "show server\r\n" );
				recv3 = recv( socket: soc, length: 2048, timeout: 10 );
				typerecv = eregmatch( pattern: "Ident String: ([a-zA-Z0-9]+)", string: bin2string( ddata: recv3, noprint_replacement: "" ) );
				if(!isnull( typerecv[1] )){
					type = typerecv[1];
				}
			}
			close( soc );
		}
		exit( 0 );
	}
	set_kb_item( name: "lantronix_device/telnet/" + port + "/type", value: type );
	if(mac = eregmatch( pattern: "MAC address ([0-9a-fA-F]{12})", string: bin2string( ddata: banner, noprint_replacement: "" ) )){
		plain_mac = mac[1];
		for(i = 0;i < 12;i++){
			full_mac += plain_mac[i];
			if(i % 2 && i != 11){
				full_mac += ":";
			}
		}
		register_host_detail( name: "MAC", value: full_mac, desc: "Get the MAC Address via Lantronix Telnet banner" );
		replace_kb_item( name: "Host/mac_address", value: full_mac );
	}
}
exit( 0 );

