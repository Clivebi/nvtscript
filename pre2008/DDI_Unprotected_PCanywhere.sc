if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10798" );
	script_version( "2019-04-10T13:42:28+0000" );
	script_tag( name: "last_modification", value: "2019-04-10 13:42:28 +0000 (Wed, 10 Apr 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0508" );
	script_name( "Unprotected PC Anywhere Service" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2002 Digital Defense Incorporated" );
	script_family( "General" );
	script_dependencies( "find_service.sc", "PC_anywhere_tcp.sc", "os_detection.sc" );
	script_require_ports( "Services/pcanywheredata", 5631 );
	script_mandatory_keys( "Host/runs_windows" );
	script_tag( name: "solution", value: "1. Open the PC Anywhere application as an Administrator.

  2. Right click on the Host object you are using and select Properties.

  3. Select the Caller Access tab.

  4. Switch the authentication type to Windows or PC Anywhere.

  5. If you are using PC Anywhere authentication, set a strong password." );
	script_tag( name: "summary", value: "The PC Anywhere service does not require a password to access
  the desktop of this system. If this machine is running Windows 95, 98, or ME, gaining full control
  of the machine is trivial. If this system is running NT or 2000 and is currently logged out, an
  attacker can still spy on and hijack a legitimate user's session when they login." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
cl[0] = raw_string( 0x00, 0x00, 0x00, 0x00 );
sv[0] = "nter";
cl[1] = raw_string( 0x6f, 0x06, 0xff );
sv[1] = raw_string( 0x1b, 0x61 );
cl[2] = raw_string( 0x6f, 0x61, 0x00, 0x09, 0x00, 0xfe, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00, 0x00, 0x00 );
sv[2] = raw_string( 0x1b, 0x62 );
cl[3] = raw_string( 0x6f, 0x62, 0x01, 0x02, 0x00, 0x00, 0x00 );
sv[3] = raw_string( 0x65, 0x6e );
cl[4] = raw_string( 0x6f, 0x49, 0x00, 0x4c, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x20, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1f, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x09, 0xff, 0x05, 0x00, 0x00, 0x00, 0x60, 0x24, 0x00, 0x09, 0x00, 0x00, 0x00, 0x06, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x31 );
sv[4] = raw_string( 0x1b, 0x16 );
cl[5] = raw_string( 0x6f, 0x73, 0x02, 0x01, 0x00, 0x02 );
sv[5] = "Service Pack";
port = get_kb_item( "Services/pcanywheredata" );
if(!port){
	port = 5631;
}
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
for(d = 0;cl[d];d++){
	send( socket: soc, data: cl[d] );
	r = recv( socket: soc, length: 2048 );
	if(!r){
		exit( 0 );
	}
	if(d == 2){
		if(( ContainsString( r, "Reducing" ) ) && ( ContainsString( r, "encryption" ) )){
			}
		if(( ContainsString( r, "denying" ) ) && ( ContainsString( r, "cannot connect at level" ) )){
			exit( 0 );
		}
	}
	if(d == 3){
		if(( ContainsString( r, "Enter user name" ) ) || ( ContainsString( r, "Enter login name" ) )){
			exit( 0 );
		}
	}
	if(ContainsString( r, !sv[d] )){
		close( soc );
		exit( 0 );
	}
	security_message( port: port );
	close( soc );
	exit( 0 );
}
exit( 99 );

