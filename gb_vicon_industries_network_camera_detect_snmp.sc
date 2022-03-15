if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107333" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2018-07-23 12:16:49 +0200 (Mon, 23 Jul 2018)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Vicon Industries Network Camera Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Vicon Industries Network Cameras." );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("snmp_func.inc.sc");
require("misc_func.inc.sc");
port = snmp_get_port( default: 161 );
if(!sysdesc = snmp_get_sysdescr( port: port )){
	exit( 0 );
}
if(IsMatchRegexp( sysdesc, "IQinVision" )){
	set_kb_item( name: "vicon_industries/network_camera/detected", value: TRUE );
	set_kb_item( name: "vicon_industries/network_camera/snmp/detected", value: TRUE );
	set_kb_item( name: "vicon_industries/network_camera/snmp/port", value: port );
	version = "unknown";
	type = "unknown";
	vers = eregmatch( pattern: "(V|B|Version )(V[0-9.]+)", string: sysdesc, icase: FALSE );
	if(vers[2]){
		version = vers[2];
	}
	type = eregmatch( pattern: "IQ(eye)?([0578ADMPR])", string: sysdesc, icase: FALSE );
	type_list["0"] = "3 Series / 4 Series";
	type_list["5"] = "5 Series";
	type_list["7"] = "7 Series";
	type_list["8"] = "Sentinel Series";
	type_list["9"] = "9 Series";
	type_list["A"] = "Alliance-pro";
	type_list["D"] = "Alliance-mini";
	type_list["M"] = "Alliance-mx";
	type_list["P"] = "PTZ";
	type_list["R"] = "R5 Series";
	if( type_list[type[2]] ){
		type = type_list[type[2]];
	}
	else {
		type = "unknown";
	}
	set_kb_item( name: "vicon_industries/network_camera/snmp/" + port + "/type", value: type );
	set_kb_item( name: "vicon_industries/network_camera/snmp/" + port + "/version", value: version );
	set_kb_item( name: "vicon_industries/network_camera/snmp/" + port + "/concluded", value: sysdesc );
}
exit( 0 );

