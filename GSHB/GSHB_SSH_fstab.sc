if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96094" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-06-21 10:39:50 +0200 (Mon, 21 Jun 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Read /etc/fstab and search for Volumes with reiserfs" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "find_service.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to Read /etc/fstab and search for Volumes with reiserfs." );
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
	set_kb_item( name: "GSHB/FSTAB/reiserfs", value: "error" );
	set_kb_item( name: "GSHB/FSTAB/log", value: error );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/FSTAB/reiserfs", value: "windows" );
	exit( 0 );
}
fstab = ssh_cmd( socket: sock, cmd: "grep -v '^#' /etc/fstab" );
if(IsMatchRegexp( fstab, ".*Datei oder Verzeichnis nicht gefunden.*" ) || IsMatchRegexp( fstab, ".*No such file or directory.*" )){
	fstab = "none";
}
if( fstab != "none" && ContainsString( fstab, "reiserfs" ) ){
	Lst = split( buffer: fstab, keep: 0 );
	for(i = 0;i < max_index( Lst );i++){
		if(!ContainsString( Lst[i], "reiserfs" )){
			continue;
		}
		val += Lst[i] + "\n";
	}
	fstab = val;
}
else {
	fstab = "noreiserfs";
}
set_kb_item( name: "GSHB/FSTAB/reiserfs", value: fstab );
exit( 0 );

