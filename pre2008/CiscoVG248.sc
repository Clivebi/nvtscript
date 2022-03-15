if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.19377" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2006-03-26 17:55:15 +0200 (Sun, 26 Mar 2006)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Cisco VG248 login password is blank" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 Rick McCloskey" );
	script_family( "CISCO" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "solution", value: "Telnet to this unit and at the configuration interface:
  Choose Configure-> and set the login and enable passwords. If
  possible, in the future do not use telnet since it is an insecure protocol." );
	script_tag( name: "impact", value: "The Cisco VG248 does not have a password set and allows direct
  access to the configuration interface. An attacker could telnet to the Cisco unit and reconfigure
  it to lock the owner out as well as completely disable the phone system." );
	script_tag( name: "summary", value: "The remote host is a Cisco VG248 with a blank password." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = telnet_get_port( default: 23 );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
banner = telnet_negotiate( socket: soc );
banner += line = recv_line( socket: soc, length: 4096 );
n = 0;
for(;IsMatchRegexp( line, "^ " );){
	line = recv_line( socket: soc, length: 4096 );
	banner += line;
	n++;
	if(n > 100){
		close( soc );
		exit( 0 );
	}
}
close( soc );
if(ContainsString( banner, "Main menu" ) && ContainsString( banner, "Configure" ) && ContainsString( banner, "Display" )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

