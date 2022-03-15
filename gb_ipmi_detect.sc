if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103835" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-11-10T15:30:28+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 15:30:28 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2013-11-26 11:39:47 +0100 (Tue, 26 Nov 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "IPMI Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Service detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_require_udp_ports( 623 );
	script_tag( name: "summary", value: "An IPMI Service is running at this host.

The Intelligent Platform Management Interface (IPMI) is a standardized computer system
interface used by system administrators for out-of-band management of computer systems
and monitoring of their operation." );
	exit( 0 );
}
require("host_details.inc.sc");
require("byte_func.inc.sc");
require("port_service_func.inc.sc");
port = 623;
if(!get_udp_port_state( port )){
	exit( 0 );
}
rmcp = raw_string( 0x06, 0x00, 0xff, 0x07 );
gcac = raw_string( 0x38 );
header = rmcp + raw_string( 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0x20, 0x18, 0xc8, 0x81, 0x00 ) + gcac;
level = raw_string( 0x04 );
ipmi_20 = header + raw_string( 0x8e ) + level + raw_string( 0xb5 );
ipmi_15 = header + raw_string( 0x0e ) + level + raw_string( 0x35 );
reqs = make_list( ipmi_20,
	 ipmi_15 );
for req in reqs {
	soc = open_sock_udp( port );
	if(!soc){
		exit( 0 );
	}
	send( socket: soc, data: req );
	recv = recv( socket: soc, length: 128 );
	close( soc );
	if(!IsMatchRegexp( hexstr( recv ), "0600ff07" ) || strlen( recv ) < 24){
		continue;
	}
	if(ord( recv[20] ) != 0){
		continue;
	}
	auth_support = dec2bin( dec: ord( recv[22] ) );
	if(auth_support){
		if(auth_support[7] == 1){
			set_kb_item( name: "ipmi/no_auth_supported", value: TRUE );
		}
		if(auth_support[6] == 1){
			set_kb_item( name: "ipmi/md2_supported", value: TRUE );
		}
	}
	ipmi_version = dec2bin( dec: ord( recv[24] ) );
	ipmi_vers_str = "v1.5";
	if(ipmi_version){
		if(ipmi_version[6] == 1){
			set_kb_item( name: "ipmi/version/2.0", value: TRUE );
			ipmi_vers_str += " v2.0";
		}
	}
	non_null = dec2bin( dec: ord( recv[23] ) );
	if(non_null){
		if(non_null[7] == 1){
			set_kb_item( name: "ipmi/anonymous_login", value: TRUE );
		}
		if(non_null[6] == 1){
			set_kb_item( name: "ipmi/null_username", value: TRUE );
		}
	}
	service_register( port: port, ipproto: "udp", proto: "ipmi", message: "An IPMI service is running at this port. Supported IPMI version(s): " + ipmi_vers_str + "\n" );
	log_message( data: "An IPMI service is running at this port. Supported IPMI version(s): " + ipmi_vers_str + "\n", port: 623, proto: "udp" );
	exit( 0 );
}
exit( 0 );

