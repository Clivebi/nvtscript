if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96090" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-05-12 13:28:00 +0200 (Wed, 12 May 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Check if NTFS Access Control Lists and NTFS Alternate Data Streams supported" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_dependencies( "compliance_tests.sc", "gather-package-list.sc", "smb_nativelanman.sc", "netbios_name_get.sc" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_tag( name: "summary", value: "Check if NTFS Access Control Lists and NTFS Alternate Data Streams supported." );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("version_func.inc.sc");
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
	set_kb_item( name: "GSHB/SAMBA/NTFSADS", value: "error" );
	set_kb_item( name: "GSHB/SAMBA/ACL", value: "error" );
	set_kb_item( name: "GSHB/SAMBA/ACLSUPP", value: "error" );
	set_kb_item( name: "GSHB/SAMBA/VER", value: "error" );
	set_kb_item( name: "GSHB/SAMBA/log", value: error );
	exit( 0 );
}
samba = kb_smb_is_samba();
if( samba ){
	rpms = get_kb_item( "ssh/login/packages" );
	if( rpms ){
		pkg1 = "samba";
		pat1 = NASLString( "ii  (", pkg1, ") +([0-9]:)?([^ ]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		ver = desc1[3];
	}
	else {
		rpms = get_kb_item( "ssh/login/rpms" );
		tmp = split( buffer: rpms, keep: 0 );
		if(max_index( tmp ) <= 1){
			rpms = ereg_replace( string: rpms, pattern: ";", replace: "\n" );
		}
		pkg1 = "samba";
		pat1 = NASLString( "(", pkg1, ")~([0-9a-zA-Z/.-_/+]+)~([0-9a-zA-Z/.-_]+)" );
		desc1 = eregmatch( pattern: pat1, string: rpms );
		ver = desc1[2];
	}
	if( version_is_greater_equal( version: ver, test_version: "3.2.0" ) ) {
		NTFSADS = "yes";
	}
	else {
		NTFSADS = "no";
	}
	fstab = ssh_cmd( socket: sock, cmd: "grep -v '^#' /etc/fstab" );
	if( !ContainsString( fstab, "acl," ) && !ContainsString( fstab, ",acl" ) ) {
		ACL = "no";
	}
	else {
		Lst = split( buffer: fstab, keep: 0 );
		for(i = 0;i < max_index( Lst );i++){
			if(ContainsString( Lst[i], "acl," ) || ContainsString( Lst[i], ",acl" )){
				ACL += Lst[i] + "\n";
			}
		}
	}
	smbconf = ssh_cmd( socket: sock, cmd: "grep -v '^#' /etc/samba/smb.conf" );
	smbconf = tolower( smbconf );
	if( ContainsString( smbconf, "nt acl support = yes" ) ) {
		ACLSUPP = "yes";
	}
	else {
		ACLSUPP = "no";
	}
	set_kb_item( name: "GSHB/SAMBA/NTFSADS", value: NTFSADS );
	set_kb_item( name: "GSHB/SAMBA/ACL", value: ACL );
	set_kb_item( name: "GSHB/SAMBA/ACLSUPP", value: ACLSUPP );
	set_kb_item( name: "GSHB/SAMBA/VER", value: ver );
}
else {
	set_kb_item( name: "GSHB/SAMBA/NTFSADS", value: "none" );
	set_kb_item( name: "GSHB/SAMBA/ACL", value: "none" );
	set_kb_item( name: "GSHB/SAMBA/ACLSUPP", value: "none" );
	set_kb_item( name: "GSHB/SAMBA/VER", value: "none" );
}
exit( 0 );

