if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144722" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2020-10-08 06:50:04 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-19 15:07:00 +0000 (Mon, 19 Oct 2020)" );
	script_cve_id( "CVE-2020-24218" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_name( "HiSilicon Encoder Default Credentials (Telnet)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/mult_dvr_or_radio/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "HiSilicon Encoder devices are using default credentials over Telnet." );
	script_tag( name: "vuldetect", value: "Tries to login with default credentials and checks the response." );
	script_tag( name: "impact", value: "Successful exploitation would allow attackers to gain complete administrative
  access to the host." );
	script_tag( name: "affected", value: "HiSilicon Encoders. Other products might be vulnerable as well." );
	script_tag( name: "solution", value: "Change the default password for the administrative account 'root' for Telnet." );
	script_xref( name: "URL", value: "https://kojenov.com/2020-09-15-hisilicon-encoder-vulnerabilities/#root-access-via-telnet-cve-2020-24218" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("dump.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("telnet_func.inc.sc");
require("port_service_func.inc.sc");
port = telnet_get_port( default: 23 );
if(!banner = telnet_get_banner( port: port )){
	exit( 0 );
}
if(!ContainsString( banner, "(none) login:" )){
	exit( 0 );
}
username = "root";
passwords = make_list( "neworange88888888",
	 "newsheen" );
for password in passwords {
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	banner = telnet_negotiate( socket: soc );
	if(!banner || !ContainsString( banner, "(none) login:" )){
		telnet_close_socket( socket: soc );
		continue;
	}
	send( socket: soc, data: username + "\r\n" );
	recv = recv( socket: soc, length: 128 );
	if(!recv || !ContainsString( recv, "Password:" )){
		telnet_close_socket( socket: soc, data: recv );
		continue;
	}
	send( socket: soc, data: password + "\r\n" );
	recv = recv( socket: soc, length: 128 );
	telnet_close_socket( socket: soc, data: recv );
	if(recv && ContainsString( recv, "Welcome to HiLinux" )){
		report = "It was possible to log in with username \"" + username + "\" and password \"" + password + "\".";
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );
