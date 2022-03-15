if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10998" );
	script_version( "2019-06-06T07:39:31+0000" );
	script_tag( name: "last_modification", value: "2019-06-06 07:39:31 +0000 (Thu, 06 Jun 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0508" );
	script_name( "Shiva LanRover Blank Password" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "This script is Copyright (C) 2002 Digital Defense Incorporated" );
	script_family( "Privilege escalation" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/shiva/lanrover/detected" );
	script_tag( name: "solution", value: "Telnet to this device and change the
  password for the root account via the passwd command. Please ensure any other
  accounts have strong passwords set." );
	script_tag( name: "summary", value: "The Shiva LanRover has no password set for the
  root user account." );
	script_tag( name: "impact", value: "An attacker is able to telnet to this system and
  gain access to any phone lines attached to this device. Additionally, the LanRover
  can be used as a relay point for further attacks via the telnet and rlogin functionality
  available from the administration shell." );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("dump.inc.sc");
port = 23;
if(!get_port_state( port )){
	exit( 0 );
}
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "@ Userid:" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(soc){
	r = telnet_negotiate( socket: soc );
	if(ContainsString( r, "@ Userid:" )){
		send( socket: soc, data: NASLString( "root\\r\\n" ) );
		r = recv( socket: soc, length: 4096 );
		if(ContainsString( r, "Password?" )){
			send( socket: soc, data: NASLString( "\\r\\n" ) );
			r = recv( socket: soc, length: 4096 );
			if(ContainsString( r, "Shiva LanRover" )){
				security_message( port: port );
			}
		}
	}
	close( soc );
}

