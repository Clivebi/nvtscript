if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112710" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-03-11 14:52:00 +0000 (Wed, 11 Mar 2020)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "Kronos 4500 Time Clock Telnet Default Credentials" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2020 Simmons Foods, Inc." );
	script_dependencies( "telnet.sc", "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/vxworks/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Kronos 4500 Time Clock has default credentials set." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify the system configuration." );
	script_tag( name: "vuldetect", value: "Connects to the telnet service and tries to login with default credentials." );
	script_tag( name: "solution", value: "Set or change the password for 'SuperUser' or, if possible, disable the default account." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("telnet_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(!banner || !ContainsString( banner, "VxWorks login:" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
user = "SuperUser";
pass = "2323098716";
recv = recv( socket: soc, length: 512, timeout: 60 );
if(ContainsString( recv, "VxWorks login:" )){
	send( socket: soc, data: user + "\r\n" );
	recv = recv( socket: soc, length: 128, timeout: 60 );
	if(ContainsString( recv, "Password:" )){
		send( socket: soc, data: pass + "\r\n" );
		recv = recv( socket: soc, length: 512, timeout: 60 );
		if(ContainsString( recv, "->" )){
			send( socket: soc, data: "whoami\r\n" );
			recv2 = recv( socket: soc, length: 512, timeout: 60 );
			telnet_close_socket( socket: soc, data: recv );
			if(ContainsString( recv2, user )){
				report = "It was possible to login using the following credentials:\n\n" + user + ":" + pass;
				security_message( port: port, data: report );
				exit( 0 );
			}
		}
	}
}
telnet_close_socket( socket: soc );
exit( 99 );

