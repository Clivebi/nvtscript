if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96097" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-02 09:25:45 +0200 (Wed, 02 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Check the System if Opie-Server and Opie-Client installed" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "compliance_tests.sc", "gather-package-list.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_tag( name: "summary", value: "Check the System if Opie-Server and Opie-Client are installed.

  Read /etc/pam.d/opie, List Files und /etc/pam.d/ with -include opie- entry,
  Read ChallengeResponseAuthentication entry in /etc/ssh/sshd_config" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("smb_nt.inc.sc");
port = get_preference( "auth_port_ssh" );
if(!port){
	port = ssh_get_port( default: 22, ignore_unscanned: TRUE );
}
sock = ssh_login_or_reuse_connection();
if(!sock){
	error = ssh_get_error();
	if(!error){
		error = "No SSH Port or Connection!";
	}
	log_message( port: port, data: error );
	set_kb_item( name: "GSHB/OPIE/SERVICES", value: "error" );
	set_kb_item( name: "GSHB/OPIE/PAM", value: "error" );
	set_kb_item( name: "GSHB/OPIE/SSH", value: "error" );
	set_kb_item( name: "GSHB/OPIE/SERVER", value: "error" );
	set_kb_item( name: "GSHB/OPIE/CLIENT", value: "error" );
	set_kb_item( name: "GSHB/OPIE/log", value: error );
	exit( 0 );
}
SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item( "ssh/login/uname" );
if( SAMBA || ( SSHUNAME && ( !ContainsString( SSHUNAME, "command not found" ) && !ContainsString( SSHUNAME, "CYGWIN" ) ) ) ){
	rpms = get_kb_item( "ssh/login/packages" );
	if( rpms ){
		pkg1 = "opie-server";
		pkg2 = "opie-client";
		pat1 = NASLString( "ii  (", pkg1, ") +([0-9]:)?([^ ]+)" );
		pat2 = NASLString( "ii  (", pkg2, ") +([0-9]:)?([^ ]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		desc2 = eregmatch( pattern: pat2, string: rpms );
	}
	else {
		rpms = get_kb_item( "ssh/login/rpms" );
		tmp = split( buffer: rpms, keep: 0 );
		if(max_index( tmp ) <= 1){
			rpms = ereg_replace( string: rpms, pattern: ";", replace: "\n" );
		}
		pkg1 = "opie-server";
		pkg2 = "opie-client";
		pkg3 = "opie~";
		pat1 = NASLString( "(", pkg1, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)" );
		pat2 = NASLString( "(", pkg2, ")~([0-9/.]+)~([0-9a-zA-Z/.-_]+)" );
		pat3 = NASLString( "(", pkg3, ")([0-9/.]+)~([0-9a-zA-Z/.-_]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		desc2 = eregmatch( pattern: pat2, string: rpms );
		desc3 = eregmatch( pattern: pat3, string: rpms );
	}
	if( desc1 || desc3 ) {
		OPIESERVER = "yes";
	}
	else {
		OPIESERVER = "no";
	}
	if( desc2 || desc3 ) {
		OPIECLIENT = "yes";
	}
	else {
		OPIECLIENT = "no";
	}
	if( OPIESERVER == "yes" && OPIECLIENT == "yes" ) {
		pam_opie = ssh_cmd( socket: sock, cmd: "cat /etc/pam.d/opie" );
	}
	else {
		pam_opie = "noopie";
	}
	if( OPIESERVER == "yes" && OPIECLIENT == "yes" ) {
		services_opie = ssh_cmd( socket: sock, cmd: "grep \"include opie\" /etc/pam.d/*" );
	}
	else {
		services_opie = "noopie";
	}
	if( OPIESERVER == "yes" && OPIECLIENT == "yes" ) {
		ssh_opie = ssh_cmd( socket: sock, cmd: "grep \"ChallengeResponseAuthentication\" /etc/ssh/sshd_config" );
	}
	else {
		ssh_opie = "noopie";
	}
	if(ContainsString( pam_opie, "cat: command not found" )){
		pam_opie = "nocat";
	}
	if(IsMatchRegexp( pam_opie, ".*Keine Berechtigung.*" ) || IsMatchRegexp( pam_opie, ".*Permission denied.*" )){
		pam_opie = "norights";
	}
	if(ContainsString( pam_opie, "cat: /etc/pam.d/opie" )){
		pam_opie = "nopamopie";
	}
	if(pam_opie == ""){
		pam_opie = "empty";
	}
	if(ContainsString( services_opie, "grep: command not found" )){
		services_opie = "nogrep";
	}
	if(IsMatchRegexp( services_opie, ".*Keine Berechtigung.*" ) || IsMatchRegexp( services_opie, ".*Permission denied.*" )){
		services_opie = "norights";
	}
	if(services_opie == ""){
		services_opie = "empty";
	}
	if(ContainsString( ssh_opie, "grep: command not found" )){
		ssh_opie = "nogrep";
	}
	if(IsMatchRegexp( ssh_opie, ".*Keine Berechtigung.*" ) || IsMatchRegexp( ssh_opie, ".*Permission denied.*" )){
		ssh_opie = "norights";
	}
	if(ssh_opie == ""){
		ssh_opie = "empty";
	}
}
else {
	OPIESERVER = "windows";
	OPIECLIENT = "windows";
}
set_kb_item( name: "GSHB/OPIE/SERVICES", value: services_opie );
set_kb_item( name: "GSHB/OPIE/PAM", value: pam_opie );
set_kb_item( name: "GSHB/OPIE/SSH", value: ssh_opie );
set_kb_item( name: "GSHB/OPIE/CLIENT", value: OPIECLIENT );
set_kb_item( name: "GSHB/OPIE/SERVER", value: OPIESERVER );
exit( 0 );

