if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105079" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-03-24T10:08:26+0000" );
	script_tag( name: "last_modification", value: "2021-03-24 10:08:26 +0000 (Wed, 24 Mar 2021)" );
	script_tag( name: "creation_date", value: "2014-09-04 09:48:32 +0200 (Thu, 04 Sep 2014)" );
	script_name( "Cisco IOS XR Detection (SNMP)" );
	script_tag( name: "summary", value: "This script performs SNMP based detection of Cisco IOS XR." );
	script_category( ACT_GATHER_INFO );
	script_family( "Product detection" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_snmp_sysdescr_detect.sc" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	script_mandatory_keys( "SNMP/sysdescr/available" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("snmp_func.inc.sc");
source = "snmp";
port = snmp_get_port( default: 161 );
sysdesc = snmp_get_sysdescr( port: port );
if(!sysdesc){
	exit( 0 );
}
if(!ContainsString( sysdesc, "Cisco IOS XR" )){
	exit( 0 );
}
set_kb_item( name: "cisco_ios_xr/detected", value: TRUE );
version = eregmatch( pattern: "Cisco IOS XR Software.*Version ([0-9.]+)", string: sysdesc );
if(isnull( version[1] )){
	exit( 0 );
}
cpe = "cpe:/o:cisco:ios_xr:" + version[1];
set_kb_item( name: "cisco_ios_xr/" + source + "/version", value: version[1] );
set_kb_item( name: "Host/OS/SNMP", value: "Cisco IOS XR" );
set_kb_item( name: "Host/OS/SNMP/Confidence", value: 100 );
type = eregmatch( pattern: "Cisco IOS XR Software \\(Cisco ([^)]+)\\)", string: sysdesc );
if(!isnull( type[1] )){
	set_kb_item( name: "cisco_ios_xr/" + source + "/model", value: type[1] );
}
report = "The remote host is running IOS XR ";
if(type[1]){
	report += "(" + type[1] + ") ";
}
report += version[1] + "\nCPE: " + cpe + "\nConcluded: " + sysdesc + "\n";
log_message( data: report, port: port, proto: "udp" );
exit( 0 );

