if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107328" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-07-12 13:43:57 +0200 (Thu, 12 Jul 2018)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_cve_id( "CVE-2018-12925" );
	script_name( "Lantronix Devices Authentication Bypass Vulnerability" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "gb_lantronix_device_version.sc" );
	script_mandatory_keys( "lantronix_device/detected" );
	script_tag( name: "summary", value: "Lantronix devices do not require a password for telnet access." );
	script_tag( name: "vuldetect", value: "Checks if the target device is vulnerable." );
	script_tag( name: "impact", value: "If not configured manually the device has no password authentication enabled by default.
  Attackers can gain access, gather information about the internal network and try to elevate their provileges." );
	script_tag( name: "affected", value: "Lantronixs Devices with telnet access." );
	script_tag( name: "solution", value: "Consult the documentation of your device to set a proper username/password combination
  and/or restrict remote telnet access." );
	exit( 0 );
}
require("host_details.inc.sc");
port = get_kb_item( "lantronix_device/telnet/port" );
username = "login";
if( !get_kb_item( "lantronix_device/telnet/" + port + "/access" ) ){
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	recv1 = recv( socket: soc, length: 2048, timeout: 10 );
	if(ContainsString( recv1, "prompt for assistance" ) && ContainsString( recv1, "Username>" )){
		send( socket: soc, data: username + "\r\n" );
		recv2 = recv( socket: soc, length: 2048, timeout: 10 );
		close( soc );
		if(IsMatchRegexp( recv2, "Local_.+>" )){
			vuln = TRUE;
			set_kb_item( name: "lantronix_device/telnet/" + port + "/access", value: TRUE );
		}
	}
}
else {
	vuln = TRUE;
}
if(soc){
	close( soc );
}
if(vuln){
	report = "It was possible to gain telnet access with username '" + username + "' and no password.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

