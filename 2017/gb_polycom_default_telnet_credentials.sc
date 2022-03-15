if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112151" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Polycom HDX Default Telnet Credentials" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-12-08 09:24:56 +0100 (Fri, 08 Dec 2017)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/polycom/device/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://staaldraad.github.io/2017/11/12/polycom-hdx-rce/" );
	script_tag( name: "summary", value: "The Polycom device has default telnet credentials or passwordless login." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the telnet service and try to either gain direct access since no password is set or login with default credentials." );
	script_tag( name: "insight", value: "The Polycom series exposes an administrative console on port 23. This
  administrative interface is built on PSH (Polycom Shell) and allows management of
  the underlying device. By default there is no password, or the password is either
  set to 456, admin, or POLYCOM, there is no username." );
	script_tag( name: "solution", value: "It is recommended to disable the telnet access." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
port = telnet_get_port( default: 23 );
banner = telnet_get_banner( port: port );
if(ContainsString( banner, "Polycom Command Shell" ) || ContainsString( banner, "Welcome to ViewStation" ) || ( ContainsString( banner, "Hi, my name is" ) && ContainsString( banner, "Here is what I know about myself" ) )){
	if(ContainsString( banner, "Polycom Command Shell" ) || ( ContainsString( banner, "Hi, my name is" ) && ContainsString( banner, "Here is what I know about myself" ) )){
		soc = open_sock_tcp( port );
		if(!soc){
			exit( 0 );
		}
		send( socket: soc, data: "whoami\r\n" );
		recv = recv( socket: soc, length: 2048 );
		close( soc );
		if(ContainsString( recv, "Hi, my name is" ) && ContainsString( recv, "Here is what I know about myself" )){
			VULN = TRUE;
			report = "It was possible to gain access via telnet without entering any credentials.";
		}
	}
	if(ContainsString( banner, "Welcome to ViewStation" )){
		report = "It was possible to login via telnet using one or more of the following default credentials:\n";
		passwords = make_list( "456",
			 "admin",
			 "POLYCOM" );
		for pass in passwords {
			soc = open_sock_tcp( port );
			if(!soc){
				exit( 0 );
			}
			recv = recv( socket: soc, length: 2048 );
			if(ContainsString( recv, "Password" )){
				send( socket: soc, data: pass + "\r\n" );
				recv = recv( socket: soc, length: 1024 );
				if(ContainsString( recv, "Polycom Command Shell" )){
					send( socket: soc, data: "whoami\r\n" );
					recv = recv( socket: soc, length: 2048 );
					if(ContainsString( recv, "Hi, my name is" ) && ContainsString( recv, "Here is what I know about myself" )){
						VULN = TRUE;
						report += "\nPassword: " + pass;
					}
				}
			}
			close( soc );
		}
	}
	if(VULN){
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

