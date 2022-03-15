if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17293" );
	script_version( "2020-08-25T06:55:13+0000" );
	script_tag( name: "last_modification", value: "2020-08-25 06:55:13 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-1999-1420", "CVE-1999-1421" );
	script_bugtraq_id( 212 );
	script_name( "Default password 'debug' for account 'user'" );
	script_category( ACT_ATTACK );
	script_family( "Default Accounts" );
	script_copyright( "Copyright (C) 2005 Michel Arboi" );
	script_dependencies( "find_service.sc", "telnet.sc", "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23, "Services/ssh", 22 );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "The account 'user' has the password 'debug'." );
	script_tag( name: "solution", value: "Set a strong password for this account or disable it." );
	script_tag( name: "impact", value: "An attacker may use it to gain further privileges on this system." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("ssh_func.inc.sc");
require("telnet_func.inc.sc");
require("default_account.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
account = "user";
password = "debug";
port = check_account( login: account, password: password );
if(port){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

