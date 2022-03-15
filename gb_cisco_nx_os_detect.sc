if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103799" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2013-10-09 16:24:09 +0200 (Wed, 09 Oct 2013)" );
	script_name( "Cisco NX-OS Detection (SNMP)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Cisco NX-OS." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("dump.inc.sc");
require("snmp_func.inc.sc");
func parse_result( data ){
	if(strlen( data ) < 8){
		return FALSE;
	}
	for(v = 0;v < strlen( data );v++){
		if(ord( data[v] ) == 43 && ord( data[v - 1] ) == 13){
			ok = TRUE;
			break;
		}
		oid_len = ord( data[v] );
	}
	if(!ok || oid_len < 8){
		return FALSE;
	}
	tmp = substr( data, ( v + oid_len + 2 ) );
	if(tmp && !isprint( c: tmp[0] )){
		tmp = substr( tmp, 1, strlen( tmp ) - 1 );
	}
	return tmp;
}
func map_model( mod ){
	if(mod == "n1000v"){
		return "1000V";
	}
	if(mod == "n9000"){
		return "N9K";
	}
	if(mod == "n8000"){
		return "8000";
	}
	if(mod == "n7000"){
		return "7000";
	}
	if(mod == "n6000"){
		return "6000";
	}
	if(mod == "n5000"){
		return "5000";
	}
	if(mod == "n4000"){
		return "4000";
	}
	if(mod == "n3500"){
		return "3500";
	}
	if(mod == "n3000"){
		return "3000";
	}
	if(mod == "n2000"){
		return "2000";
	}
}
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(!ContainsString( sysdesc, "Cisco NX-OS" )){
	exit( 0 );
}
set_kb_item( name: "cisco/nx_os/detected", value: TRUE );
nx_version = eregmatch( pattern: "Version ([^,]+),", string: sysdesc );
if(isnull( nx_version[1] )){
	exit( 0 );
}
nx_ver = nx_version[1];
set_kb_item( name: "cisco/nx_os/snmp/version", value: nx_ver );
model = "unknown";
device = "unknown";
source = "snmp";
community = snmp_get_community( port: port );
if(!community){
	community = "public";
}
SNMP_BASE = 40;
COMMUNITY_SIZE = strlen( community );
sz = COMMUNITY_SIZE % 256;
len = SNMP_BASE + COMMUNITY_SIZE;
for(i = 0;i < 3;i++){
	soc = open_sock_udp( port );
	if(!soc){
		continue;
	}
	sendata = raw_string( 0x30, len, 0x02, 0x01, i, 0x04, sz ) + community + raw_string( 0xa0, 0x21, 0x02, 0x04, 0x7f, 0x45, 0x71, 0x96, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00, 0x30, 0x13, 0x30, 0x11, 0x06, 0x0d, 0x2b, 0x06, 0x01, 0x02, 0x01, 0x2f, 0x01, 0x01, 0x01, 0x01, 0x02, 0x81, 0x15, 0x05, 0x00 );
	send( socket: soc, data: sendata );
	result = recv( socket: soc, length: 400, timeout: 1 );
	close( soc );
	if(!result || ord( result[0] ) != 48){
		continue;
	}
	if(!res = parse_result( data: result )){
		continue;
	}
	if( ContainsString( res, "Nexus" ) || IsMatchRegexp( res, "^N9K" ) ){
		device = "Nexus";
		if( IsMatchRegexp( res, "^N9K-" ) ) {
			model = res;
		}
		else {
			m = eregmatch( pattern: "Nexus\\s*([^\\r\\n\\s]+)[^\\r\\n]*\\s+Chassis", string: res );
			if(!isnull( m[1] )){
				model = m[1];
			}
		}
		break;
	}
	else {
		if(ContainsString( res, "MDS" )){
			device = "MDS";
			m = eregmatch( pattern: "MDS\\s*([^\\r\\n\\s]+)[^\\r\\n]*\\s+Chassis", string: res );
			if(!isnull( m[1] )){
				model = m[1];
			}
			break;
		}
	}
}
if(device == "unknown"){
	if( ContainsString( sysdesc, "titanium" ) ){
		device = "MDS";
	}
	else {
		if(IsMatchRegexp( sysdesc, "Cisco NX-OS\\(tm\\) (n[0-9]+[^,]+)" )){
			device = "Nexus";
			tmp_model = eregmatch( pattern: "Cisco NX-OS\\(tm\\) (n[0-9]+[^,]+)", string: sysdesc );
			if(!isnull( tmp_model[1] )){
				model = map_model( mod: tmp_model[1] );
			}
		}
	}
}
set_kb_item( name: "cisco/nx_os/" + source + "/device", value: device );
set_kb_item( name: "cisco/nx_os/" + source + "/model", value: model );
exit( 0 );

