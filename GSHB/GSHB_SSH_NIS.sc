if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96102" );
	script_version( "2021-06-17T11:20:59+0000" );
	script_tag( name: "last_modification", value: "2021-06-17 11:20:59 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-05-07 15:05:51 +0200 (Fri, 07 May 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Test System if NIS Server or Client is installed" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "compliance_tests.sc", "gather-package-list.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_tag( name: "summary", value: "Test System if NIS Server or Client is installed." );
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
	set_kb_item( name: "GSHB/NIS/server", value: "error" );
	set_kb_item( name: "GSHB/NIS/client", value: "error" );
	set_kb_item( name: "GSHB/NIS/ypbind", value: "error" );
	set_kb_item( name: "GSHB/NIS/ypserv", value: "error" );
	set_kb_item( name: "GSHB/NIS/NisPlusUserwopw", value: "error" );
	set_kb_item( name: "GSHB/NIS/NisPlusGenUserwopw", value: "error" );
	set_kb_item( name: "GSHB/NIS/NisPlusUserwpw", value: "error" );
	set_kb_item( name: "GSHB/NIS/NisPlusGenUserwpw", value: "error" );
	set_kb_item( name: "GSHB/NIS/LocalUID0", value: "error" );
	set_kb_item( name: "GSHB/NIS/NisPlusGroupwopw", value: "error" );
	set_kb_item( name: "GSHB/NIS/NisPlusGenGroupwopw", value: "error" );
	set_kb_item( name: "GSHB/NIS/NisPlusGroupwpw", value: "error" );
	set_kb_item( name: "GSHB/NIS/NisPlusGenGroupwpw", value: "error" );
	set_kb_item( name: "GSHB/NIS/hostsdeny", value: "error" );
	set_kb_item( name: "GSHB/NIS/hostsallow", value: "error" );
	set_kb_item( name: "GSHB/NIS/securenets", value: "error" );
	set_kb_item( name: "GSHB/NIS/log", value: error );
	exit( 0 );
}
SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item( "ssh/login/uname" );
if( SAMBA || ( SSHUNAME && ( !ContainsString( SSHUNAME, "command not found" ) && !ContainsString( SSHUNAME, "CYGWIN" ) ) ) ){
	rpms = get_kb_item( "ssh/login/packages" );
	if( rpms ){
		pkg1 = "nis";
		pkg2 = "yp-tools";
		pkg3 = "ypbind";
		pkg4 = "ypserv";
		pkg5 = "rpcbind";
		pkg6 = "portmap";
		pat1 = NASLString( "ii  (", pkg1, ") +([0-9]:)?([^ ]+)" );
		pat2 = NASLString( "ii  (", pkg2, ") +([0-9]:)?([^ ]+)" );
		pat3 = NASLString( "ii  (", pkg3, ") +([0-9]:)?([^ ]+)" );
		pat4 = NASLString( "ii  (", pkg4, ") +([0-9]:)?([^ ]+)" );
		pat5 = NASLString( "ii  (", pkg5, ") +([0-9]:)?([^ ]+)" );
		pat6 = NASLString( "ii  (", pkg6, ") +([0-9]:)?([^ ]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		desc2 = eregmatch( pattern: pat2, string: rpms );
		desc3 = eregmatch( pattern: pat3, string: rpms );
		desc4 = eregmatch( pattern: pat4, string: rpms );
		desc5 = eregmatch( pattern: pat5, string: rpms );
		desc6 = eregmatch( pattern: pat6, string: rpms );
	}
	else {
		rpms = get_kb_item( "ssh/login/rpms" );
		tmp = split( buffer: rpms, keep: FALSE );
		if(max_index( tmp ) <= 1){
			rpms = ereg_replace( string: rpms, pattern: ";", replace: "\n" );
		}
		pkg1 = "nis";
		pkg2 = "yp-tools";
		pkg3 = "ypbind";
		pkg4 = "ypserv";
		pkg5 = "rpcbind";
		pkg6 = "portmap";
		pat1 = NASLString( "(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		pat2 = NASLString( "(", pkg2, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		pat3 = NASLString( "(", pkg3, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		pat4 = NASLString( "(", pkg4, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		pat5 = NASLString( "(", pkg5, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		pat6 = NASLString( "(", pkg6, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		desc2 = eregmatch( pattern: pat2, string: rpms );
		desc3 = eregmatch( pattern: pat3, string: rpms );
		desc4 = eregmatch( pattern: pat4, string: rpms );
		desc5 = eregmatch( pattern: pat5, string: rpms );
		desc6 = eregmatch( pattern: pat6, string: rpms );
	}
	if( desc1 || desc4 ) {
		nisserver = "yes";
	}
	else {
		nisserver = "no";
	}
	if( ( desc1 && ( desc5 || desc6 ) ) || ( desc2 && desc3 && ( desc5 || desc6 ) ) ) {
		nisclient = "yes";
	}
	else {
		nisclient = "no";
	}
	passwd = ssh_cmd( socket: sock, cmd: "cat /etc/passwd" );
	group = ssh_cmd( socket: sock, cmd: "cat /etc/group" );
	ypbind = ssh_cmd( socket: sock, cmd: "ps -C ypbind" );
	if( !ContainsString( ypbind, "bash: /bin/ps:" ) ){
		Lst = split( buffer: ypbind, keep: FALSE );
		if( ContainsString( Lst[1], "ypbind" ) ) {
			ypbind = "yes";
		}
		else {
			ypbind = "no";
		}
	}
	else {
		ypbind = ssh_cmd( socket: sock, cmd: "rpcinfo -u localhost ypbind" );
		if(ContainsString( ypbind, "is not available" ) || ContainsString( ypbind, "ist nicht verfügbar" )){
			ypbind = "no";
		}
		if( ContainsString( ypbind, "ready and waiting" ) || ContainsString( ypbind, "ist bereit und wartet" ) ) {
			ypbind = "yes";
		}
		else {
			ypbind = "unknown";
		}
	}
	ypserv = ssh_cmd( socket: sock, cmd: "ps -C ypserv" );
	if( !ContainsString( ypserv, "bash: /bin/ps:" ) ){
		Lst = split( buffer: ypserv, keep: FALSE );
		if( ContainsString( Lst[1], "ypserv" ) ) {
			ypserv = "yes";
		}
		else {
			ypserv = "no";
		}
	}
	else {
		ypserv = ssh_cmd( socket: sock, cmd: "rpcinfo -u localhost ypserv" );
		if(ContainsString( ypserv, "is not available" ) || ContainsString( ypserv, "ist nicht verfügbar" )){
			ypserv = "no";
		}
		if( ContainsString( ypserv, "ready and waiting" ) || ContainsString( ypserv, "ist bereit und wartet" ) ) {
			ypserv = "yes";
		}
		else {
			ypserv = "unknown";
		}
	}
}
else {
	nisserver = "windows";
	nisclient = "windows";
}
Lst = split( buffer: passwd, keep: FALSE );
for(i = 0;i < max_index( Lst );i++){
	if(ContainsString( Lst[i], "+::0:0:::" )){
		NisPlusUserwopw = "yes";
	}
	if(ContainsString( Lst[i], "+::::::" )){
		NisPlusGenUserwopw = "yes";
	}
	if(ContainsString( Lst[i], "+:*:0:0:::" )){
		NisPlusUserwpw = "yes";
	}
	if(ContainsString( Lst[i], "+:*:::::" )){
		NisPlusGenUserwpw = "yes";
	}
	if( IsMatchRegexp( Lst[i], "^\\+.*:.*:0:0:.*:.*:.*" ) ) {
		userval = "yes";
	}
	else {
		if(IsMatchRegexp( Lst[i], "^\\+.*::0:0:.*:.*:.*" )){
			userval = "yes";
		}
	}
	if(IsMatchRegexp( Lst[i], "^[^\\+]*:.*:0:0:.*:.*:.*" )){
		if( userval != "yes" ) {
			LocalUID0 = "first";
		}
		else {
			LocalUID0 = "not first";
		}
	}
}
Lst = split( buffer: group, keep: FALSE );
for(i = 0;i < max_index( Lst );i++){
	if(ContainsString( Lst[i], "+::0:" )){
		NisPlusGroupwopw = "yes";
	}
	if(ContainsString( Lst[i], "+:::" )){
		NisPlusGenGroupwopw = "yes";
	}
	if(ContainsString( Lst[i], "+:*:0:" )){
		NisPlusGroupwpw = "yes";
	}
	if(ContainsString( Lst[i], "+:*::" )){
		NisPlusGenGroupwpw = "yes";
	}
}
securenets = ssh_cmd( socket: sock, cmd: "grep -v '^#' /etc/ypserv.securenets" );
hostsdeny = ssh_cmd( socket: sock, cmd: "grep -v '^#' /etc/hosts.deny | grep ypserv:" );
hostsallow = ssh_cmd( socket: sock, cmd: "grep -v '^#' /etc/hosts.allow | grep ypserv:" );
if(!hostsdeny || hostsdeny == ""){
	hostsdeny = "noentry";
}
if(!hostsallow || hostsallow == ""){
	hostsallow = "noentry";
}
if(ContainsString( securenets, "0.0.0.0" )){
	Lst = split( buffer: securenets, keep: FALSE );
	for(i = 0;i < max_index( Lst );i++){
		if(IsMatchRegexp( Lst[i], "(#).*(0\\.0\\.0\\.0.*0\\.0\\.0\\.0)" )){
			continue;
		}
		if(IsMatchRegexp( Lst[i], ".*(0\\.0\\.0\\.0.*0\\.0\\.0\\.0)" )){
			securenetsval = "everybody";
		}
	}
}
if(!NisPlusUserwopw){
	NisPlusUserwopw = "no";
}
if(!NisPlusGenUserwopw){
	NisPlusGenUserwopw = "no";
}
if(!NisPlusUserwpw){
	NisPlusUserwpw = "no";
}
if(!NisPlusGenUserwpw){
	NisPlusGenUserwpw = "no";
}
if(!NisPlusUserwpw){
	NisPlusUserwpw = "no";
}
if(!NisPlusGroupwopw){
	NisPlusGroupwopw = "no";
}
if(!NisPlusGenGroupwopw){
	NisPlusGenGroupwopw = "no";
}
if(!NisPlusGroupwpw){
	NisPlusGroupwpw = "no";
}
if(!NisPlusGenGroupwpw){
	NisPlusGenGroupwpw = "no";
}
if(!LocalUID0){
	LocalUID0 = "no";
}
if(!securenetsval){
	securenetsval = "none";
}
set_kb_item( name: "GSHB/NIS/server", value: nisserver );
set_kb_item( name: "GSHB/NIS/client", value: nisclient );
set_kb_item( name: "GSHB/NIS/ypbind", value: ypbind );
set_kb_item( name: "GSHB/NIS/ypserv", value: ypserv );
set_kb_item( name: "GSHB/NIS/NisPlusUserwopw", value: NisPlusUserwopw );
set_kb_item( name: "GSHB/NIS/NisPlusGenUserwopw", value: NisPlusGenUserwopw );
set_kb_item( name: "GSHB/NIS/NisPlusUserwpw", value: NisPlusUserwpw );
set_kb_item( name: "GSHB/NIS/NisPlusGenUserwpw", value: NisPlusGenUserwpw );
set_kb_item( name: "GSHB/NIS/LocalUID0", value: LocalUID0 );
set_kb_item( name: "GSHB/NIS/NisPlusGroupwopw", value: NisPlusGroupwopw );
set_kb_item( name: "GSHB/NIS/NisPlusGenGroupwopw", value: NisPlusGenGroupwpw );
set_kb_item( name: "GSHB/NIS/NisPlusGroupwpw", value: NisPlusGroupwpw );
set_kb_item( name: "GSHB/NIS/NisPlusGenGroupwpw", value: NisPlusGenGroupwpw );
set_kb_item( name: "GSHB/NIS/hostsdeny", value: hostsdeny );
set_kb_item( name: "GSHB/NIS/hostsallow", value: hostsallow );
set_kb_item( name: "GSHB/NIS/securenets", value: securenetsval );
exit( 0 );

