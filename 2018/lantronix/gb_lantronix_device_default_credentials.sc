if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107329" );
	script_version( "2019-09-06T14:17:49+0000" );
	script_tag( name: "last_modification", value: "2019-09-06 14:17:49 +0000 (Fri, 06 Sep 2019)" );
	script_tag( name: "creation_date", value: "2018-07-12 18:29:24 +0200 (Thu, 12 Jul 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_cve_id( "CVE-2018-14018" );
	script_name( "Lantronix Devices Default Credentials Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_lantronix_device_version.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "lantronix_device/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "Lantronix devices have a default useraccount 'root' with password 'system' which grants
  admin rights TELNET access." );
	script_tag( name: "vuldetect", value: "Tries to login using default credentials." );
	script_tag( name: "impact", value: "Using the command 'set privilege' followed by entering the password 'system' enables the
  attacker to gather information, change configurations, telnet to other hosts etc." );
	script_tag( name: "affected", value: "Lantronix devices with telnet access." );
	script_tag( name: "solution", value: "Consult your documentation how to change default credentials and/or disable remote access
  to the device." );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("host_details.inc.sc");
port = get_kb_item( "lantronix_device/telnet/port" );
if(!get_kb_item( "lantronix_device/telnet/" + port + "/access" )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
username = "root";
password = "system";
recv1 = recv( socket: soc, length: 2048, timeout: 10 );
if(ContainsString( recv1, "prompt for assistance" ) && ContainsString( recv1, "Username>" )){
	send( socket: soc, data: username + "\r\n" );
	recv2 = recv( socket: soc, length: 2048, timeout: 10 );
	if(IsMatchRegexp( recv2, "Local_.+>" )){
		send( socket: soc, data: "set privileged\r\n" );
		recv3 = recv( socket: soc, length: 2048, timeout: 10 );
		if(ContainsString( recv3, "Password>" )){
			send( socket: soc, data: "system\r\n\r\n" );
			recv4 = recv( socket: soc, length: 2048, timeout: 10 );
			close( soc );
			if(IsMatchRegexp( recv4, "Local_.+>>" )){
				vuln = TRUE;
				set_kb_item( name: "lantronix_device/telnet/" + port + "/full_access", value: TRUE );
			}
		}
	}
}
if(soc){
	close( soc );
}
if(vuln){
	report = "It was possible to gain unrestricted telnet access with username '" + username + "' and password '" + password + "'.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

