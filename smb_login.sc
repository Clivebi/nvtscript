if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.10394" );
	script_version( "2021-08-11T09:39:10+0000" );
	script_tag( name: "last_modification", value: "2021-08-11 09:39:10 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "creation_date", value: "2008-09-10 10:22:48 +0200 (Wed, 10 Sep 2008)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Windows" );
	script_name( "SMB log in" );
	script_dependencies( "smb_authorization.sc", "netbios_name_get.sc", "lsc_options.sc", "cifs445.sc", "find_service.sc", "logins.sc", "global_settings.sc" );
	script_require_keys( "SMB/name", "SMB/transport" );
	script_exclude_keys( "global_settings/authenticated_scans_disabled" );
	script_require_ports( 139, 445 );
	script_tag( name: "summary", value: "This script attempts to logon into the remote host using
  login/password credentials." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
if(get_kb_item( "global_settings/authenticated_scans_disabled" )){
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
func remote_login( login, passwd, domain, name, port ){
	var login, passwd, domain, name, port;
	var login_defined, soc, r, prot, uid, tid;
	login_defined = 0;
	soc = open_sock_tcp( port );
	if(!soc){
		return login_defined;
	}
	r = smb_session_request( soc: soc, remote: name );
	if(!r){
		close( soc );
		return login_defined;
	}
	prot = smb_neg_prot( soc: soc );
	if(!prot){
		close( soc );
		return login_defined;
	}
	r = smb_session_setup( soc: soc, login: login, password: passwd, domain: domain, prot: prot );
	if(!r){
		close( soc );
		return login_defined;
	}
	uid = session_extract_uid( reply: r );
	if(!uid){
		close( soc );
		return login_defined;
	}
	r = smb_tconx( soc: soc, name: name, uid: uid, share: "IPC$" );
	if(!r){
		close( soc );
		return login_defined;
	}
	close( soc );
	if( r ){
		tid = tconx_extract_tid( reply: r );
		login_defined = 1;
	}
	else {
		login_defined = 0;
	}
	return login_defined;
}
port = kb_smb_transport();
if(!port){
	port = 139;
}
if(!get_port_state( port )){
	exit( 0 );
}
name = kb_smb_name();
if(!name){
	name = "*SMBSERVER";
}
login = NASLString( get_kb_item( "SMB/login_filled/0" ) );
password = NASLString( get_kb_item( "SMB/password_filled/0" ) );
user_domain = NASLString( get_kb_item( "SMB/domain_filled/0" ) );
if(!user_domain){
	if(ContainsString( login, "\\" )){
		matched_domain = eregmatch( pattern: ".*\\\\", string: login );
		if(!isnull( matched_domain[0] )){
			user_domain = ereg_replace( pattern: "\\\\", replace: "", string: matched_domain[0] );
		}
	}
	if(ContainsString( login, "@" )){
		matched_domain = eregmatch( pattern: "@.*", string: login );
		if(!isnull( matched_domain[0] )){
			user_domain = ereg_replace( pattern: "@", replace: "", string: matched_domain[0] );
			if(IsMatchRegexp( user_domain, ".*\\..*" )){
				fqdn_domain = eregmatch( pattern: ".*\\.", string: user_domain );
				if(!isnull( fqdn_domain[0] )){
					user_domain = ereg_replace( pattern: "\\.$", replace: "", string: fqdn_domain[0] );
				}
			}
		}
	}
}
if(ContainsString( login, "\\" )){
	user_login = eregmatch( pattern: "\\\\.*", string: login );
	if(ContainsString( user_login[0], "\\" )){
		login = ereg_replace( pattern: "\\\\", replace: "", string: user_login[0] );
	}
}
if(ContainsString( login, "@" )){
	user_login = eregmatch( pattern: ".*@", string: login );
	if(ContainsString( user_login[0], "@" )){
		login = ereg_replace( pattern: "@", replace: "", string: user_login[0] );
	}
}
if(!strlen( login )){
	login = "";
}
if(!strlen( password )){
	password = "";
}
if(strlen( user_domain )){
	domain = user_domain;
}
if(!strlen( user_domain )){
	flag = 1;
	domain = NASLString( get_kb_item( "SMB/DOMAIN" ) );
	if(!domain){
		domain = NASLString( get_kb_item( "SMB/workgroup" ) );
	}
	if(!domain){
		domain = "";
	}
}
set_kb_item( name: "SMB/login", value: login );
set_kb_item( name: "SMB/password", value: password );
if(domain && flag != 1){
	set_kb_item( name: "SMB/domain", value: domain );
}
if( flag == 1 && !strlen( user_domain ) ){
	login_defined = remote_login( login: login, passwd: password, domain: "", name: name, port: port );
}
else {
	login_defined = remote_login( login: login, passwd: password, domain: domain, name: name, port: port );
}
if( login_defined == 1 ){
	register_host_detail( name: "Auth-SMB-Success", value: "Protocol SMB, Port " + port + ", User " + login );
	log_message( port: port, data: "It was possible to log into the remote host using the SMB protocol." );
	set_kb_item( name: "login/SMB/success", value: TRUE );
	set_kb_item( name: "login/SMB/success/port", value: port );
}
else {
	if(( login_defined == 0 ) && login){
		register_host_detail( name: "Auth-SMB-Failure", value: "Protocol SMB, Port " + port + ", User " + login );
		log_message( port: port, data: "It was NOT possible to log into the remote host using the SMB protocol." );
		set_kb_item( name: "login/SMB/failed", value: TRUE );
		set_kb_item( name: "login/SMB/failed/port", value: port );
	}
}
exit( 0 );

