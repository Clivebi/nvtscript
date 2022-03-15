if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11133" );
	script_version( "2020-11-09T11:11:32+0000" );
	script_tag( name: "last_modification", value: "2020-11-09 11:11:32 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_name( "Generic format string" );
	script_category( ACT_DESTRUCTIVE_ATTACK );
	script_copyright( "Copyright (C) 2002 Michel Arboi" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc" );
	script_require_ports( "Services/unknown" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/81565" );
	script_tag( name: "solution", value: "Upgrade your software or contact your vendor and inform it of this
  vulnerability." );
	script_tag( name: "summary", value: "The remote service is vulnerable to a format string attack
  An attacker may use this flaw to execute arbitrary code on this host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = unknownservice_get_port( nodefault: TRUE );
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "xxxxxxxxxxxxxxxxxxxxxxxxxx" );
r1 = recv( socket: soc, length: 256, min: 1 );
close( soc );
flag = 1;
if(egrep( pattern: "[0-9a-fA-F]{4}", string: r1 )){
	flag = 0;
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: crap( length: 256, data: "%#0123456x%04x%x%s%p%n%d%o%u%c%h%l%q%j%z%Z%t%i%e%g%f%a%C%S%04x%%#0123456x%%x%%s%%p%%n%%d%%o%%u%%c%%h%%l%%q%%j%%z%%Z%%t%%i%%e%%g%%f%%a%%C%%S%%04x" ) );
r2 = recv( socket: soc, length: 256, min: 1 );
close( soc );
soc = open_sock_tcp( port );
if(!soc){
	security_message( port: port );
	exit( 0 );
}
close( soc );
if(flag && egrep( pattern: "[0-9a-fA-F]{4}", string: r2 )){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

