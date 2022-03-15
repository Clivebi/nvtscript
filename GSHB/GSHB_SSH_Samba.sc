if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96093" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-05-25 17:00:55 +0200 (Tue, 25 May 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Read Samba [global] and [netlogon] Configuration" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to Read Samba [global] and [netlogon] Configuration." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
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
	set_kb_item( name: "GSHB/SAMBA/global", value: "error" );
	set_kb_item( name: "GSHB/SAMBA/netlogon", value: "error" );
	set_kb_item( name: "GSHB/SAMBA/smbpasswd", value: "error" );
	set_kb_item( name: "GSHB/SAMBA/secretstdb", value: "error" );
	set_kb_item( name: "GSHB/SAMBA/log", value: error );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/SAMBA/global", value: "windows" );
	set_kb_item( name: "GSHB/SAMBA/netlogon", value: "windows" );
	set_kb_item( name: "GSHB/SAMBA/smbpasswd", value: "windows" );
	set_kb_item( name: "GSHB/SAMBA/secretstdb", value: "windows" );
	exit( 0 );
}
smbpasswd = ssh_cmd( socket: sock, cmd: "ls -l /etc/smbpasswd" );
secretstdb = ssh_cmd( socket: sock, cmd: "ls -l /var/lib/samba/secrets.tdb" );
smbconf = ssh_cmd( socket: sock, cmd: "egrep -v '^(#|;)' /etc/samba/smb.conf" );
if(IsMatchRegexp( smbconf, ".*Datei oder Verzeichnis nicht gefunden.*" ) || IsMatchRegexp( smbconf, ".*No such file or directory.*" )){
	smbconf = "none";
}
if(IsMatchRegexp( smbpasswd, ".*Datei oder Verzeichnis nicht gefunden.*" ) || IsMatchRegexp( smbpasswd, ".*No such file or directory.*" )){
	smbpasswd = "none";
}
if(IsMatchRegexp( secretstdb, ".*Datei oder Verzeichnis nicht gefunden.*" ) || IsMatchRegexp( secretstdb, ".*No such file or directory.*" )){
	secretstdb = "none";
}
if(smbconf != "none"){
	Lst = split( buffer: smbconf, keep: 0 );
	for(i = 0;i < max_index( Lst );i++){
		if(Lst[i] == ""){
			continue;
		}
		val += Lst[i] + "\n";
	}
	if( !val ) {
		smbconf = "novalentrys";
	}
	else {
		smbconf = val;
	}
}
if( smbconf == "none" ) {
	global = "none";
}
else {
	if(smbconf != "none" && smbconf != "novalentrys"){
		val = eregmatch( string: smbconf, pattern: "global.*]", icase: 0 );
		Lst = split( buffer: val[0], keep: 0 );
		for(i = 1;i < max_index( Lst );i++){
			if( ContainsString( Lst[i], "[" ) ) {
				i = 999999;
			}
			else {
				global += Lst[i] + "\n";
			}
		}
		if(!global){
			global = "novalentrys";
		}
	}
}
if( smbconf == "none" ) {
	netlogon = "none";
}
else {
	if(smbconf != "none" && smbconf != "novalentrys"){
		val = eregmatch( string: smbconf, pattern: "netlogon.*]", icase: 0 );
		Lst = split( buffer: val[0], keep: 0 );
		for(i = 1;i < max_index( Lst );i++){
			if( ContainsString( Lst[i], "[" ) ) {
				i = 999999;
			}
			else {
				netlogon += Lst[i] + "\n";
			}
		}
		if(!netlogon){
			netlogon = "novalentrys";
		}
	}
}
set_kb_item( name: "GSHB/SAMBA/global", value: global );
set_kb_item( name: "GSHB/SAMBA/netlogon", value: netlogon );
set_kb_item( name: "GSHB/SAMBA/smbpasswd", value: smbpasswd );
set_kb_item( name: "GSHB/SAMBA/secretstdb", value: secretstdb );
exit( 0 );

