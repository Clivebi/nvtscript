if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108528" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-01-09 11:31:09 +0100 (Wed, 09 Jan 2019)" );
	script_tag( name: "cvss_base", value: "4.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:N" );
	script_name( "FTP Unencrypted Cleartext Login" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc", "gb_starttls_ftp.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/banner/available" );
	script_tag( name: "summary", value: "The remote host is running a FTP service that allows cleartext logins over
  unencrypted connections." );
	script_tag( name: "impact", value: "An attacker can uncover login names and passwords by sniffing traffic to the
  FTP service." );
	script_tag( name: "vuldetect", value: "Tries to login to a non FTPS enabled FTP service without sending a
  'AUTH TLS' command first and checks if the service is accepting the login without enforcing the use of
  the 'AUTH TLS' command." );
	script_tag( name: "solution", value: "Enable FTPS or enforce the connection via the 'AUTH TLS' command. Please see
  the manual of the FTP service for more information." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = ftp_get_port( default: 21 );
banner = ftp_get_banner( port: port );
if(!banner || !IsMatchRegexp( banner, "^2[0-9]{2}[ -].+" )){
	exit( 0 );
}
encaps = get_port_transport( port );
if(encaps > ENCAPS_IP){
	exit( 99 );
}
kb_creds = ftp_get_kb_creds();
if( kb_creds["login"] == "anonymous" || kb_creds["login"] == "ftp" ){
	vt_strings = get_vt_strings();
	creds[vt_strings["lowercase"]] = vt_strings["lowercase"] + "@example.com";
	creds[kb_creds["login"]] = kb_creds["pass"];
}
else {
	creds["anonymous"] = "anonymous@example.com";
	creds[kb_creds["login"]] = creds["pass"];
}
auth_report = "";
login_report = "";
for user in keys( creds ) {
	soc = open_sock_tcp( port );
	if(!soc){
		continue;
	}
	banner = ftp_recv_line( socket: soc );
	if(!banner || !IsMatchRegexp( banner, "^[0-9]{3}[ -].+" )){
		close( soc );
		continue;
	}
	if(!IsMatchRegexp( banner, "^2[0-9]{2}[ -].+" )){
		ftp_close( socket: soc );
		continue;
	}
	login = ftp_send_cmd( socket: soc, cmd: "USER " + user );
	if(login && IsMatchRegexp( login, "^3[0-9]{2}[ -].+" )){
		VULN = TRUE;
		if(get_kb_item( "ftp/" + port + "/starttls" )){
			AUTH_TLS = TRUE;
			if( user == "anonymous" || user == "ftp" ) {
				auth_report += "\n- Anonymous sessions";
			}
			else {
				auth_report += "\n- Non-anonymous sessions";
			}
		}
		if( user == "anonymous" || user == "ftp" ) {
			login_report += "\nAnonymous sessions:     " + chomp( login );
		}
		else {
			login_report += "\nNon-anonymous sessions: " + chomp( login );
		}
		ftp_send_cmd( socket: soc, cmd: "PASS " + creds["pass"] );
	}
	ftp_close( socket: soc );
}
if(VULN){
	report = "The remote FTP service accepts logins without a previous sent \'AUTH TLS\' command. Response(s):\n" + login_report;
	if(AUTH_TLS){
		report += "\n\nThe remote FTP service supports the \'AUTH TLS\' command but isn\'t enforcing the use of it for:\n" + auth_report;
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

