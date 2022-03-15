if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11855" );
	script_version( "2020-11-10T09:46:51+0000" );
	script_tag( name: "last_modification", value: "2020-11-10 09:46:51 +0000 (Tue, 10 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "RemoteNC detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 J.Mlodzianowski" );
	script_family( "Malware" );
	script_dependencies( "find_service2.sc", "JM_FsSniffer.sc" );
	script_require_ports( "Services/RemoteNC", 19340 );
	script_xref( name: "URL", value: "http://www.rapter.net/jm2.htm" );
	script_tag( name: "solution", value: "See the references for details on the removal." );
	script_tag( name: "impact", value: "An attacker may use it to steal your passwords." );
	script_tag( name: "summary", value: "This host appears to be running RemoteNC on this port.

  RemoteNC is a Backdoor which allows an intruder gain remote control of your computer." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( default: 19340, proto: "RemoteNC" );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = recv( socket: soc, min: 1, length: 30 );
close( soc );
if(!r){
	exit( 0 );
}
if(ContainsString( r, "RemoteNC Control Password:" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

