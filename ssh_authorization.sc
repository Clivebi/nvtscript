if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.90022" );
	script_version( "2021-07-27T13:33:00+0000" );
	script_tag( name: "last_modification", value: "2021-07-27 13:33:00 +0000 (Tue, 27 Jul 2021)" );
	script_tag( name: "creation_date", value: "2007-11-01 23:55:52 +0100 (Thu, 01 Nov 2007)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "SSH Authorization Check" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2007-2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "find_service.sc", "ssh_authorization_init.sc", "global_settings.sc", "lsc_options.sc" );
	script_mandatory_keys( "Secret/SSH/login" );
	script_exclude_keys( "global_settings/authenticated_scans_disabled" );
	script_tag( name: "summary", value: "This script tries to login with provided credentials.

  If the login was successful, it marks this port as available for any authenticated tests." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
if(get_kb_item( "global_settings/authenticated_scans_disabled" )){
	exit( 0 );
}
require("ssh_func.inc.sc");
require("host_details.inc.sc");
port = kb_ssh_transport();
if( kb_ssh_login() && ( kb_ssh_password() || kb_ssh_privatekey() ) ){
	if(!port){
		reason = "No port for an SSH connect was found open. Hence authenticated checks are not enabled.";
		log_message( data: reason );
		set_kb_item( name: "login/SSH/failed", value: TRUE );
		set_kb_item( name: "login/SSH/failed/reason", value: reason );
		register_host_detail( name: "Auth-SSH-Failure", value: "Protocol SSH, User " + kb_ssh_login() + " : No port open" );
		exit( 0 );
	}
	sock = ssh_login_or_reuse_connection();
	if(!sock){
		reason = "It was not possible to login using the provided SSH credentials. Hence authenticated checks are not enabled.";
		log_message( port: port, data: reason );
		set_kb_item( name: "login/SSH/failed", value: TRUE );
		set_kb_item( name: "login/SSH/failed/port", value: port );
		set_kb_item( name: "login/SSH/failed/reason", value: reason );
		register_host_detail( name: "Auth-SSH-Failure", value: "Protocol SSH, Port " + port + ", User " + kb_ssh_login() + " : Login failure" );
		ssh_close_connection();
		exit( 0 );
	}
	res = ssh_cmd( socket: sock, cmd: "echo 'login test'", timeout: 60, pty: TRUE, return_errors: FALSE );
	if(res){
		for text in ssh_expired_pw_text {
			if(ContainsString( res, text )){
				reason = "The password of the provided SSH credentials has expired and the user is required to change it before a login is possible again. Hence authenticated checks are not enabled.";
				log_message( port: port, data: reason );
				set_kb_item( name: "login/SSH/failed", value: TRUE );
				set_kb_item( name: "login/SSH/failed/port", value: port );
				set_kb_item( name: "login/SSH/failed/reason", value: reason );
				register_host_detail( name: "Auth-SSH-Failure", value: "Protocol SSH, Port " + port + ", User " + kb_ssh_login() + " : Password expired" );
				ssh_close_connection();
				exit( 0 );
			}
		}
	}
	if(( su_user = ssh_kb_privlogin() ) && ( !get_kb_item( "login/SSH/priv/failed" ) )){
		priv_enabled = TRUE;
		res2 = ssh_cmd( socket: sock, cmd: "whoami", timeout: 60, pty: FALSE, ignore_force_pty: TRUE, return_errors: FALSE );
		res2 = chomp( res2 );
		if(!res2 || res2 != su_user){
			reason = "It was not possible to switch user with the provided SSH 'su' credentials. Hence authenticated checks are not enabled.";
			log_message( port: port, data: reason );
			set_kb_item( name: "login/SSH/priv/failed", value: TRUE );
			set_kb_item( name: "login/SSH/failed", value: TRUE );
			set_kb_item( name: "login/SSH/failed/port", value: port );
			set_kb_item( name: "login/SSH/failed/reason", value: reason );
			register_host_detail( name: "Auth-SSH-Failure", value: "Protocol SSH, Port " + port + ", 'su' User " + su_user + " : Switch user failed" );
			ssh_close_connection();
			exit( 0 );
		}
	}
	ssh_close_connection();
	set_kb_item( name: "login/SSH/success", value: TRUE );
	set_kb_item( name: "login/SSH/success/port", value: port );
	if( priv_enabled ){
		host_detail_report = "Protocol SSH, Port " + port + ", User " + kb_ssh_login() + ", 'su' User " + su_user;
		log_msg_report = "It was possible to login using the provided SSH credentials and to switch user with the provided SSH 'su' credentials. Hence authenticated checks are enabled.";
	}
	else {
		host_detail_report = "Protocol SSH, Port " + port + ", User " + kb_ssh_login();
		log_msg_report = "It was possible to login using the provided SSH credentials. Hence authenticated checks are enabled.";
	}
	register_host_detail( name: "Auth-SSH-Success", value: host_detail_report );
	log_message( port: port, data: log_msg_report );
}
else {
	}
exit( 0 );

