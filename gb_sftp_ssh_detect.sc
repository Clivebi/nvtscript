if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117628" );
	script_version( "2021-09-02T13:03:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-02 13:03:31 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-09-02 09:44:22 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Secure File Transfer Protocol (SFTP) Detection (SSH)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_dependencies( "ssh_authorization.sc", "global_settings.sc", "ssh_detect.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-21.04/en/scanning.html#creating-a-target" );
	script_xref( name: "URL", value: "https://docs.greenbone.net/GSM-Manual/gos-21.04/en/scanning.html#credentials" );
	script_tag( name: "summary", value: "Determines if the Secure File Transfer Protocol (SFTP) is
  enabled on the remote SSH service.

  Note: Valid SSH credentials needs to be provided in the target configuration for a successful
  detection. Please see the references for more information." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
SCRIPT_NAME = "Secure File Transfer Protocol (SFTP) Detection (SSH)";
debug_enabled = get_kb_item( "global_settings/ssh/debug" );
if(!defined_func( "sftp_enabled_check" )){
	if(debug_enabled){
		log_message( port: 0, data: "** " + SCRIPT_NAME + " DEBUG **: Required 'sftp_enabled_check' function not provided by the scanner (scanner too old?)." );
	}
	exit( 0 );
}
require("ssh_func.inc.sc");
require("port_service_func.inc.sc");
require("host_details.inc.sc");
login = kb_ssh_login();
password = kb_ssh_password();
privkey = kb_ssh_privatekey();
passphrase = kb_ssh_passphrase();
if(!login && ( !password && !privkey )){
	if(debug_enabled){
		log_message( port: 0, data: "** " + SCRIPT_NAME + " DEBUG **: Required SSH credentials are missing / not provided in the target configuration." );
	}
	exit( 0 );
}
port = kb_ssh_transport();
soc = open_sock_tcp( port );
if(!soc){
	if(debug_enabled){
		log_message( port: port, data: "** " + SCRIPT_NAME + " DEBUG **: open_sock_tcp(): Failed to open a TCP connection to the remote SSH service." );
	}
	exit( 0 );
}
sess = ssh_connect( socket: soc );
if(!sess){
	if(debug_enabled){
		log_message( port: port, data: "** " + SCRIPT_NAME + " DEBUG **: ssh_connect(): Failed to setup an SSH session to the remote SSH service." );
	}
	exit( 0 );
}
auth_successful = ssh_userauth( session: sess, login: login, password: password, privatekey: privkey, passphrase: passphrase );
if(isnull( auth_successful ) || auth_successful){
	if( isnull( auth_successful ) ) {
		reason = "NULL (failure during SSH session ID verification)";
	}
	else {
		reason = auth_successful + " (libssh error code)";
	}
	if(debug_enabled){
		log_message( port: port, data: "** " + SCRIPT_NAME + " DEBUG **: ssh_userauth(): Failed to authenticate against the remote SSH service. Reason: " + reason );
	}
	ssh_disconnect( sess );
	exit( 0 );
}
sftp_status = sftp_enabled_check( sess );
ssh_disconnect( sess );
if( isnull( sftp_status ) ){
	if(debug_enabled){
		log_message( port: port, data: "** " + SCRIPT_NAME + " DEBUG **: sftp_enabled_check(): Unable to determine SFTP status of the remote SSH service. Reason: NULL (failure during SSH session ID verification)" );
	}
}
else {
	if( sftp_status == 0 ){
		report = "SFTP is enabled on the remote SSH service.";
		service_register( port: port, proto: "sftp-ssh", message: "An SSH service supporting the Secure File Transfer Protocol (SFTP) seems to be running on this port" );
	}
	else {
		if( sftp_status == -1 ){
			report = "SFTP is disabled on the remote SSH service.";
		}
		else {
			if(debug_enabled){
				log_message( port: port, data: "** " + SCRIPT_NAME + " DEBUG **: sftp_enabled_check(): Unable to determine SFTP status of the remote SSH service. Reason: " + sftp_status + " (libssh error code)" );
			}
		}
	}
}
if(report){
	log_message( port: port, data: report );
}
exit( 0 );

