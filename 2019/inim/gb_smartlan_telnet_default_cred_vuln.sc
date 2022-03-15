CPE = "cpe:/a:inim:smartlan_g";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.143258" );
	script_version( "2020-12-23T10:59:58+0000" );
	script_tag( name: "last_modification", value: "2020-12-23 10:59:58 +0000 (Wed, 23 Dec 2020)" );
	script_tag( name: "creation_date", value: "2019-12-17 03:16:07 +0000 (Tue, 17 Dec 2019)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Inim SmartLAN Hardcoded Credentials (Telnet)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_inim_smartlan_consolidation.sc", "gb_default_credentials_options.sc" );
	script_mandatory_keys( "inim/smartlan/telnet/detected" );
	script_require_ports( "Services/telnet", 23 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "SmartLAN devices utilize hardcoded credentials within its Linux distribution
  image." );
	script_tag( name: "insight", value: "The devices utilize hard-coded credentials within its Linux distribution
  image. These sets of credentials are never exposed to the end-user and cannot be changed through any normal
  operation of the smart home device." );
	script_tag( name: "impact", value: "An attacker could exploit this vulnerability by logging in and gain system access" );
	script_tag( name: "vuldetect", value: "The script tries to login via Telnet with the default credentials." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_xref( name: "URL", value: "https://www.zeroscience.mk/en/vulnerabilities/ZSL-2019-5546.php" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("dump.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("telnet_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "telnet" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
creds = make_array( "root", "pass", "logout", "logout" );
found = make_array();
for user in keys( creds ) {
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	recv = telnet_negotiate( socket: soc );
	if(ContainsString( recv, "login:" )){
		send( socket: soc, data: user + "\r\n" );
		recv = recv( socket: soc, length: 512 );
		if(ContainsString( recv, "Password:" )){
			send( socket: soc, data: creds[user] + "\r\n" );
			recv = recv( socket: soc, length: 1024 );
			if(!ContainsString( recv, "Login incorrect" )){
				send( socket: soc, data: "id\r\n" );
				recv = recv( socket: soc, length: 1024 );
				if(IsMatchRegexp( recv, "uid=[0-9]+.*gid=[0-9]+.*" )){
					found[user] = creds[user];
				}
			}
		}
	}
	close( soc );
}
for user in keys( found ) {
	report += "\nUsername: " + user + "   Password: " + found[user];
}
if(report){
	report = "It was possible to login with the following credentials:\n" + report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

