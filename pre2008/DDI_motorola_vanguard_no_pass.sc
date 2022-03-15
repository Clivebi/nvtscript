if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11203" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-1999-0508" );
	script_name( "Motorola Vanguard with No Password" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2003 Digital Defense" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "solution", value: "Please set a strong password for this device." );
	script_tag( name: "summary", value: "This device is a Motorola Vanguard router and has
  no password set. An attacker can reconfigure
  this device without providing any authentication." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
func greprecv( socket, pattern ){
	var buffer, cnt, _r;
	buffer = "";
	cnt = 0;
	for(;1;){
		_r = recv_line( socket: socket, length: 4096 );
		if(strlen( _r ) == 0){
			return FALSE;
		}
		buffer = NASLString( buffer, _r );
		if(ereg( pattern: pattern, string: _r )){
			return buffer;
		}
		cnt++;
		if(cnt > 1024){
			return FALSE;
		}
	}
}
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "OK" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(soc){
	buf = greprecv( socket: soc, pattern: ".*OK.*" );
	if(!buf){
		close( soc );
		exit( 0 );
	}
	send( socket: soc, data: NASLString( "atds0\\r\\n" ) );
	buf = greprecv( socket: soc, pattern: ".*Password.*" );
	if(!buf){
		close( soc );
		exit( 0 );
	}
	send( socket: soc, data: NASLString( "\\r\\n" ) );
	buf = greprecv( socket: soc, pattern: ".*Logout.*" );
	if(buf){
		security_message( port: port );
	}
	close( soc );
}
exit( 99 );

