if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108647" );
	script_version( "2021-09-08T08:01:40+0000" );
	script_cve_id( "CVE-2019-13473" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 08:01:40 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-27 17:36:00 +0000 (Thu, 27 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-09-17 11:03:13 +0000 (Tue, 17 Sep 2019)" );
	script_name( "TELESTAR-DIGITAL GmbH Multiple Internet Radio Undocumented Telnet Service / Default Credentials" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/mult_dvr_or_radio/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://www.vulnerability-lab.com/get_content.php?id=2183" );
	script_xref( name: "URL", value: "https://www.vulnerability-db.com/?q=articles/2019/09/09/imperial-dabman-internet-radio-undocumented-telnetd-code-execution" );
	script_tag( name: "summary", value: "The internet radio products of TELESTAR-DIGITAL GmbH have an undocumented Telnet service
  with default credentials enabled." );
	script_tag( name: "affected", value: "TELESTAR Bobs Rock Radio, Dabman D10, Dabman i30 Stereo, Imperial i110, Imperial i150,
  Imperial i200, Imperial i200-cd, Imperial i400, Imperial i450, Imperial i500-bt, and Imperial i600 devices are known to be
  affected. Other devices and vendors might be affected as well." );
	script_tag( name: "impact", value: "This issue may only be exploited by an attacker a root shell on the device." );
	script_tag( name: "vuldetect", value: "Connect to the Telnet service and try to login with default credentials." );
	script_tag( name: "insight", value: "It was possible to login with the telnet credentials 'root:password'." );
	script_tag( name: "solution", value: "The vendor has released the firmware update TN81HH96-g102h-g103**a*-fb21a-3624
  which is disabling the telnet service and removing the default password." );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(!banner || !ContainsString( banner, "(none) login: " )){
	exit( 0 );
}
login = "root";
pass = "password";
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
res = telnet_negotiate( socket: soc );
if(res && ContainsString( res, "(none) login: " )){
	send( socket: soc, data: login + "\r\n" );
	sleep( 3 );
	res = recv( socket: soc, length: 128 );
	if(res && ContainsString( res, "Password:" )){
		send( socket: soc, data: pass + "\r\n" );
		sleep( 3 );
		res = recv( socket: soc, length: 1024 );
		if(res && ContainsString( res, "BusyBox" ) && ContainsString( res, "built-in shell" )){
			VULN = TRUE;
			report = "It was possible to login via Telnet using the following credentials:\n\n";
			report += "Login: " + login + ", Password: " + pass;
		}
	}
}
telnet_close_socket( socket: soc, data: res );
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );
