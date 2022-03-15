if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103716" );
	script_version( "2021-04-16T06:57:08+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_name( "CAREL pCOWeb Default Account Security Bypass Vulnerability" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/121716/CAREL-pCOWeb-1.5.0-Default-Credential-Shell-Access.html" );
	script_tag( name: "last_modification", value: "2021-04-16 06:57:08 +0000 (Fri, 16 Apr 2021)" );
	script_tag( name: "creation_date", value: "2013-05-23 11:24:55 +0200 (Thu, 23 May 2013)" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/carel/pcoweb/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The remote pCOWeb is prone to a default account authentication bypass
  vulnerability." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to
  gain access to sensitive information or modify system configuration.

  It was possible to login as user 'http' with no password." );
	script_tag( name: "solution", value: "Login with telnet and set a password or change the shell from '/bin/bash' to '/bin/nologin'." );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
require("os_func.inc.sc");
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "pCOWeb login" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
buf = telnet_negotiate( socket: soc );
if(!ContainsString( buf, "pCOWeb login" )){
	close( soc );
	exit( 0 );
}
send( socket: soc, data: "http\r\n" );
recv = recv( socket: soc, length: 4096 );
if(!IsMatchRegexp( recv, "\\[http@pCOWeb.*/\\]\\$" )){
	close( soc );
	exit( 0 );
}
files = traversal_files( "linux" );
for pattern in keys( files ) {
	file = files[pattern];
	send( socket: soc, data: "cat /" + file + "\r\n" );
	recv = recv( socket: soc, length: 8192 );
	if(egrep( string: recv, pattern: pattern )){
		security_message( data: "The target was found to be vulnerable.", port: port );
		exit( 0 );
	}
}
exit( 99 );

