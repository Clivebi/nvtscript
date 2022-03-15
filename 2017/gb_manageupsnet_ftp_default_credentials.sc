if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113052" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-11-16 11:04:05 +0100 (Thu, 16 Nov 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "Workaround" );
	script_name( "ManageUPSNET FTP Default Credentials" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/manageupsnet/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_tag( name: "summary", value: "ManageUPSNET Telnet and FTP uses remote credentials 'admin' - 'admin'." );
	script_tag( name: "vuldetect", value: "The script tries to login via FTP using the username 'admin' and the password 'admin'." );
	script_tag( name: "impact", value: "Successful exploitation would allow to gain complete administrative access to the host." );
	script_tag( name: "affected", value: "All ManageUPSNET devices version 2.6 or later." );
	script_tag( name: "solution", value: "Change the default password for the administrative account 'admin' for both Telnet and FTP." );
	script_xref( name: "URL", value: "http://005c368.netsolhost.com/pdfs/9133161c.pdf" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !ContainsString( banner, "ManageUPSnet" )){
	exit( 0 );
}
login = "admin";
pass = "admin";
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
login_success = ftp_log_in( socket: soc, user: login, pass: pass );
if(login_success){
	VULN = TRUE;
	report = "It was possible to login via FTP using the following default credentials:\n\n";
	report += "Login: " + login + ", Password: " + pass;
}
close( soc );
if(VULN){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

