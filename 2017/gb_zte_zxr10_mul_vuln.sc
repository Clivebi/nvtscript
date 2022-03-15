if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107254" );
	script_version( "2021-09-16T14:01:49+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2017-10931" );
	script_name( "ZTE ZXR10 Router Multiple Vulnerabilities" );
	script_tag( name: "last_modification", value: "2021-09-16 14:01:49 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-27 21:51:00 +0000 (Wed, 27 Sep 2017)" );
	script_tag( name: "creation_date", value: "2017-11-09 10:23:00 +0200 (Thu, 09 Nov 2017)" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/zte/zxr10/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://www.palada.net/index.php/2017/10/23/news-3819/" );
	script_tag( name: "summary", value: "ZTE ZXR10 Router has a backdoor account with hard-coded credentials." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain full
  access to sensitive information or modify system configuration." );
	script_tag( name: "vuldetect", value: "Connect to the telnet service and try to login with default credentials." );
	script_tag( name: "solution", value: "Update to version 3.00.40. For more details." );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.zte.com.cn/support/news/LoopholeInfoDetail.aspx?newsId=1008262" );
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
if(!banner || !IsMatchRegexp( banner, "Welcome to (ZXUN|ZXR10).+ of ZTE Corporation" )){
	exit( 0 );
}
creds = make_list( "who;who",
	 "zte;zte",
	 "ncsh;ncsh" );
for cred in creds {
	user_name = split( buffer: cred, sep: ";", keep: FALSE );
	name = user_name[0];
	pass = user_name[1];
	soc = open_sock_tcp( port );
	if(!soc){
		exit( 0 );
	}
	recv = recv( socket: soc, length: 2048 );
	if(ContainsString( recv, "Username:" )){
		send( socket: soc, data: tolower( name ) + "\r\n" );
		recv = recv( socket: soc, length: 128 );
		if(ContainsString( recv, "Password:" )){
			send( socket: soc, data: pass + "\r\n\r\n" );
			recv = recv( socket: soc, length: 1024 );
			if(!isnull( recv )){
				send( socket: soc, data: "?\r\n" );
				recv = recv( socket: soc, length: 1024 );
				if(ContainsString( recv, "Exec commands:" )){
					VULN = TRUE;
					report = "It was possible to login via telnet using the following credentials:\n\n";
					report += "Username: " + name + ", Password: " + pass;
					break;
				}
			}
		}
	}
	close( soc );
}
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

