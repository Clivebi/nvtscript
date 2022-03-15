if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103809" );
	script_version( "2021-04-15T13:23:31+0000" );
	script_tag( name: "last_modification", value: "2021-04-15 13:23:31 +0000 (Thu, 15 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-10-14 14:24:09 +0200 (Mon, 14 Oct 2013)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "JunOS Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of JunOS." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("dump.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("snmp_func.inc.sc");
func parse_result( data ){
	if(strlen( data ) < 8){
		return FALSE;
	}
	for(v = 0;v < strlen( data );v++){
		if(ord( data[v] ) == 43 && ord( data[v - 1] ) == 11){
			ok = TRUE;
			break;
		}
		oid_len = ord( data[v] );
	}
	if(!ok || oid_len < 8){
		return FALSE;
	}
	tmp = substr( data, ( v + oid_len + 2 ) );
	if(!isprint( c: tmp[0] )){
		tmp = substr( tmp, 1, strlen( tmp ) - 1 );
	}
	model = eregmatch( pattern: "^Juniper ([^ ]+)", string: tmp );
	if(isnull( model[1] )){
		return FALSE;
	}
	return model[1];
}
SCRIPT_DESC = "Junos SNMP Detection";
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(!ContainsString( sysdesc, "JUNOS" )){
	exit( 0 );
}
junos_version = eregmatch( pattern: "JUNOS ([0-9.]+[A-Z][^ ,]+)", string: sysdesc );
if(isnull( junos_version[1] )){
	exit( 0 );
}
junos_ver = junos_version[1];
cpe = "cpe:/o:juniper:junos:" + junos_ver;
os_register_and_report( os: "JunOS", cpe: cpe, banner_type: "SNMP sysdesc", banner: sysdesc, port: port, proto: "udp", desc: SCRIPT_DESC, runs_key: "unixoide" );
register_product( cpe: cpe, location: port + "/udp", port: port, proto: "udp", service: "snmp" );
set_kb_item( name: "Junos/Version", value: junos_ver );
set_kb_item( name: "Host/OS/SNMP", value: "JUNOS" );
set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
build = eregmatch( pattern: "Build date: ([^ ]+)", string: sysdesc );
if(!isnull( build[1] )){
	set_kb_item( name: "Junos/Build", value: build[1] );
}
report_ver = junos_ver;
if(!isnull( build[1] )){
	report_ver += ", Build: " + build[1];
}
log_message( data: "The remote host is running Junos " + report_ver + "\nCPE: " + cpe + "\nConcluded: " + sysdesc + "\n", port: port, proto: "udp" );
community = snmp_get_community( port: port );
if(!community){
	community = "public";
}
SNMP_BASE = 38;
COMMUNITY_SIZE = strlen( community );
sz = COMMUNITY_SIZE % 256;
len = SNMP_BASE + COMMUNITY_SIZE;
for(i = 0;i < 3;i++){
	soc = open_sock_udp( port );
	if(!soc){
		exit( 0 );
	}
	sendata = raw_string( 0x30, len, 0x02, 0x01, i, 0x04, sz ) + community + raw_string( 0xa0, 0x1f, 0x02, 0x04, 0x1c, 0xba, 0x54, 0x29, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x11, 0x30, 0x0f, 0x06, 0x0b, 0x2b, 0x06, 0x01, 0x04, 0x01, 0x94, 0x4c, 0x03, 0x01, 0x02, 0x00, 0x05, 0x00 );
	send( socket: soc, data: sendata );
	result = recv( socket: soc, length: 400, timeout: 1 );
	close( soc );
	if(!result || ord( result[0] ) != 48){
		continue;
	}
	if(!res = parse_result( data: result )){
		continue;
	}
	set_kb_item( name: "Junos/model", value: res );
	log_message( data: "The remote host is a Junos " + res + "\n", port: port, proto: "udp" );
	exit( 0 );
}
exit( 0 );

