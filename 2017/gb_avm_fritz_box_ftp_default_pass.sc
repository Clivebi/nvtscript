CPE = "cpe:/o:avm:fritz%21_os";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108043" );
	script_version( "2020-10-05T09:09:18+0000" );
	script_tag( name: "last_modification", value: "2020-10-05 09:09:18 +0000 (Mon, 05 Oct 2020)" );
	script_tag( name: "creation_date", value: "2017-01-11 11:00:00 +0100 (Wed, 11 Jan 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "AVM FRITZ!Box Default Password (FTP)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "gb_avm_fritz_box_detect.sc", "DDI_FTP_Any_User_Login.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "avm_fritz_box/ftp/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "This script detects if the device has a default password set." );
	script_tag( name: "vuldetect", value: "Check if it is possible to login with a default password." );
	script_tag( name: "impact", value: "This issue may be exploited by a remote attacker to gain
  access to sensitive information." );
	script_tag( name: "solution", value: "Set change the identified default password." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_app" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("ftp_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
users = make_list( "ftpuser",
	 "ftpuser-internet" );
pws = make_list( "1234",
	 "0000",
	 "admin",
	 "password",
	 "passwort" );
if(!port = get_app_port( cpe: CPE, service: "ftp" )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(ftp_broken_random_login( port: port )){
	exit( 0 );
}
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "FRITZ!Box" ) || !ContainsString( banner, "FTP server ready." )){
	exit( 0 );
}
for user in users {
	for pw in pws {
		if(!soc = ftp_open_socket( port: port )){
			continue;
		}
		if(ftp_authenticate( socket: soc, user: user, pass: pw, skip_banner: TRUE )){
			report = "It was possible to login using the following default credentials: '" + user + ":" + pw + "'.";
			security_message( port: port, data: report );
			ftp_close( socket: soc );
			exit( 0 );
		}
		ftp_close( socket: soc );
	}
}
exit( 99 );

