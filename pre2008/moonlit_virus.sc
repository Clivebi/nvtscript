if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.15586" );
	script_version( "2019-04-24T07:26:10+0000" );
	script_tag( name: "last_modification", value: "2019-04-24 07:26:10 +0000 (Wed, 24 Apr 2019)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "MoonLit Virus Backdoor" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2004 KK Liu" );
	script_family( "Malware" );
	script_dependencies( "os_detection.sc" );
	script_mandatory_keys( "Host/runs_windows" );
	script_xref( name: "URL", value: "http://securityresponse.symantec.com/avcenter/venc/data/backdoor.moonlit.html" );
	script_tag( name: "solution", value: "Ensure all MS patches are applied as well as the latest AV definitions." );
	script_tag( name: "summary", value: "The system is infected by the MoonLit virus,
  the backdoor port is open.

  Backdoor.Moonlit is a Trojan horse program that can download and execute files, and may act as a proxy server." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("host_details.inc.sc");
func doGetPortFromIP( dst ){
	var retval;
	var ip;
	ip = split( buffer: dst, sep: ".", keep: 0 );
	retval = int( ip[0] ) * 256 * 256 * 256 + int( ip[1] ) * 256 * 256 + int( ip[2] ) * 256 + int( ip[3] ) * 1;
	MAGIC = 0x6D617468;
	retval = ( ( retval >>> 5 ) | ( retval << 27 ) );
	if(( retval < 0 ) && ( retval + MAGIC >= 0 )){
		MAGIC += 1;
	}
	retval += MAGIC;
	ret2 = retval << 30;
	if( ret2 == 0 ){
		return ( ( ( ( retval >>> 3 ) + 2951 ) % 0xFAD9 ) + 1031 );
	}
	else {
		if( ( retval >>> 3 ) | ( retval << 29 ) < 0 ) {
			return ( ( ( ( ( retval >>> 3 ) | ( retval << 29 ) ) - 0xFAD9 * 41801 ) % 0xFAD9 ) + 1031 );
		}
		else {
			return ( ( ( ( retval >>> 3 ) | ( retval << 29 ) ) % 0xFAD9 ) + 1031 );
		}
	}
}
hostip = get_host_ip();
dst = NASLString( hostip );
port = doGetPortFromIP( dst: dst );
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
r = recv( socket: soc, length: 10 );
close( soc );
if(r && ( strlen( r ) == 2 )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

