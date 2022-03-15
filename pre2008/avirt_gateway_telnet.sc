if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11096" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 3901 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2002-0134" );
	script_name( "Avirt gateway insecure telnet proxy" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/banner/available" );
	script_tag( name: "solution", value: "Contact your vendor for a patch or disable this service." );
	script_tag( name: "summary", value: "It was possible to connect to the remote telnet server without
  password and to get a command prompt with the 'DOS' command." );
	script_tag( name: "impact", value: "An attacker may use this flaw to get access on your system." );
	script_tag( name: "solution_type", value: "Mitigation" );
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
cmd = NASLString( "dos\\r\\n" );
send( socket: soc, data: cmd );
res = recv( socket: soc, length: 512 );
close( soc );
flag = egrep( pattern: "^[A-Z]:\\\\.*>", string: res );
if(flag){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

