if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96088" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-05-11 16:10:57 +0200 (Tue, 11 May 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Test if Audio Server installed and list access rights of /dev/audio" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "compliance_tests.sc", "gather-package-list.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_tag( name: "summary", value: "Test if Audio Server is installed and list access rights of /dev/audio.

  This Script tests if the following Audio-Servers are installed:

  esound, paudio, pulseaudio, artsd, phonon." );
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
	set_kb_item( name: "GSHB/AUDIO/package", value: "error" );
	set_kb_item( name: "GSHB/AUDIO/devaudio", value: "error" );
	set_kb_item( name: "GSHB/AUDIO/log", value: error );
	exit( 0 );
}
SAMBA = kb_smb_is_samba();
SSHUNAME = get_kb_item( "ssh/login/uname" );
if( SAMBA || ( SSHUNAME && ( !ContainsString( SSHUNAME, "command not found" ) && !ContainsString( SSHUNAME, "CYGWIN" ) ) ) ){
	rpms = get_kb_item( "ssh/login/packages" );
	if( rpms ){
		pkg1 = "esound";
		pkg2 = "paudio";
		pkg3 = "pulseaudio";
		pkg4 = "artsd";
		pkg5 = "phonon";
		pat1 = NASLString( "ii  (", pkg1, ") +([0-9]:)?([^ ]+)" );
		pat2 = NASLString( "ii  (", pkg2, ") +([0-9]:)?([^ ]+)" );
		pat3 = NASLString( "ii  (", pkg3, ") +([0-9]:)?([^ ]+)" );
		pat4 = NASLString( "ii  (", pkg4, ") +([0-9]:)?([^ ]+)" );
		pat5 = NASLString( "ii  (", pkg5, ") +([0-9]:)?([^ ]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		desc2 = eregmatch( pattern: pat2, string: rpms );
		desc3 = eregmatch( pattern: pat3, string: rpms );
		desc4 = eregmatch( pattern: pat4, string: rpms );
		desc5 = eregmatch( pattern: pat5, string: rpms );
	}
	else {
		rpms = get_kb_item( "ssh/login/rpms" );
		tmp = split( buffer: rpms, keep: 0 );
		if(max_index( tmp ) <= 1){
			rpms = ereg_replace( string: rpms, pattern: ";", replace: "\n" );
		}
		pkg1 = "esound";
		pkg2 = "paudio";
		pkg3 = "pulseaudio";
		pkg4 = "artsd";
		pkg5 = "phonon";
		pat1 = NASLString( "(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		pat2 = NASLString( "(", pkg2, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		pat3 = NASLString( "(", pkg3, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		pat4 = NASLString( "(", pkg4, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		pat5 = NASLString( "(", pkg5, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		desc2 = eregmatch( pattern: pat2, string: rpms );
		desc3 = eregmatch( pattern: pat3, string: rpms );
		desc4 = eregmatch( pattern: pat4, string: rpms );
		desc5 = eregmatch( pattern: pat5, string: rpms );
	}
	if( desc1 || desc2 || desc3 || desc4 || desc5 ){
		if(desc1){
			package = desc1[1] + ";";
		}
		if(desc2){
			package += desc2[1] + ";";
		}
		if(desc3){
			package += desc3[1] + ";";
		}
		if(desc4){
			package += desc4[1] + ";";
		}
		if(desc5){
			package += desc5[1];
		}
	}
	else {
		package = "none";
	}
	devaudio = ssh_cmd( socket: sock, cmd: "ls -l /dev/audio" );
	if(IsMatchRegexp( devaudio, ".*Datei oder Verzeichnis nicht gefunden.*" ) || IsMatchRegexp( devaudio, ".*No such file or directory.*" )){
		devaudio = "no audio";
	}
}
else {
	package = "windows";
	devaudio = "windows";
}
if(!package){
	package = "none";
}
if(!devaudio){
	devaudio = "none";
}
set_kb_item( name: "GSHB/AUDIO/package", value: package );
set_kb_item( name: "GSHB/AUDIO/devaudio", value: devaudio );
exit( 0 );

