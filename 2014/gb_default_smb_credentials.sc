if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804449" );
	script_version( "2019-09-07T15:01:50+0000" );
	script_tag( name: "cvss_base", value: "9.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-09-07 15:01:50 +0000 (Sat, 07 Sep 2019)" );
	script_tag( name: "creation_date", value: "2014-07-04 17:14:10 +0530 (Fri, 04 Jul 2014)" );
	script_name( "SMB Brute Force Logins With Default Credentials" );
	script_category( ACT_ATTACK );
	script_family( "Brute force attacks" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "smb_authorization.sc", "netbios_name_get.sc", "cifs445.sc", "find_service.sc", "logins.sc", "gb_default_credentials_options.sc" );
	script_require_keys( "SMB/name", "SMB/transport" );
	script_exclude_keys( "default_credentials/disable_brute_force_checks" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "A number of known default credentials are tried for the login via the SMB protocol." );
	script_tag( name: "vuldetect", value: "Tries to login with a number of known default credentials via the SMB protocol." );
	script_tag( name: "solution", value: "Change the password as soon as possible." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_brute_force_checks" )){
	exit( 0 );
}
require("smb_nt.inc.sc");
require("smb_default_credentials.inc.sc");
require("misc_func.inc.sc");
func remote_login( smbLogin, passwd, smbDomain, smbName, smbPort ){
	var smbLogin, passwd, smbDomain, smbName, smbPort;
	var soc, r, prot, uid, tid;
	soc = open_sock_tcp( smbPort );
	if(!soc){
		return FALSE;
	}
	r = smb_session_request( soc: soc, remote: smbName );
	if(!r){
		close( soc );
		return FALSE;
	}
	prot = smb_neg_prot( soc: soc );
	if(!prot){
		close( soc );
		return FALSE;
	}
	r = smb_session_setup( soc: soc, login: smbLogin, password: passwd, domain: smbDomain, prot: prot );
	if(!r){
		close( soc );
		return FALSE;
	}
	uid = session_extract_uid( reply: r );
	if(!uid){
		close( soc );
		return FALSE;
	}
	r = smb_tconx( soc: soc, name: smbName, uid: uid, share: "IPC$" );
	close( soc );
	if( r ){
		return TRUE;
	}
	else {
		return FALSE;
	}
}
smbPort = kb_smb_transport();
if(!smbPort){
	smbPort = 139;
}
if(!get_port_state( smbPort )){
	exit( 0 );
}
smbName = kb_smb_name();
if(!smbName){
	smbName = "*SMBSERVER";
}
for(i = 1;i < 4;i++){
	u = rand_str( length: ( 7 + i ), charset: "abcdefghijklmnopqrstuvwxyz" );
	p = rand_str( length: ( 7 + i ), charset: "abcdefghijklmnopqrstuvwxyz0123456789" );
	login_defined = remote_login( smbLogin: u, passwd: p, smbDomain: "", smbName: smbName, smbPort: smbPort );
	if(login_defined){
		exit( 0 );
	}
	sleep( 1 );
}
login_defined = remote_login( smbLogin: "", passwd: "", smbDomain: "", smbName: smbName, smbPort: smbPort );
if(login_defined){
	exit( 0 );
}
login_defined = remote_login( smbLogin: "Guest", passwd: "", smbDomain: "", smbName: smbName, smbPort: smbPort );
if(login_defined){
	guest_empty = TRUE;
	report = NASLString( "It was possible to login with the 'Guest' user and no/an empty password via the SMB protocol to the 'IPC$' share." );
	security_message( data: report, port: smbPort );
}
login_defined = remote_login( smbLogin: "Guest", passwd: rand_str( length: 10, charset: "abcdefghijklmnopqrstuvwxyz0123456789" ), smbDomain: "", smbName: smbName, smbPort: smbPort );
if(login_defined){
	guest_all = TRUE;
}
for credential in credentials {
	user_pass = split( buffer: credential, sep: ";", keep: FALSE );
	if(isnull( user_pass[0] ) || isnull( user_pass[1] )){
		continue;
	}
	smbLogin = chomp( user_pass[0] );
	password = chomp( user_pass[1] );
	if(smbLogin == "Guest" && ( guest_empty || guest_all )){
		continue;
	}
	if(tolower( password ) == "none"){
		password = "";
	}
	login_defined = remote_login( smbLogin: smbLogin, passwd: password, smbDomain: "", smbName: smbName, smbPort: smbPort );
	if(login_defined){
		report = NASLString( "It was possible to login with the following credentials via the SMB protocol to the 'IPC$' share. <User>:<Password>\\n\\n", smbLogin, ":", password );
		security_message( data: report, port: smbPort );
	}
}
exit( 0 );

