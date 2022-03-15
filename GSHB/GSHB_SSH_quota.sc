if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.96075" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2010-04-07 15:31:43 +0200 (Wed, 07 Apr 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Check if Disk Quota activated." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "IT-Grundschutz" );
	script_mandatory_keys( "Compliance/Launch/GSHB" );
	script_dependencies( "compliance_tests.sc", "gather-package-list.sc" );
	script_tag( name: "summary", value: "This plugin uses ssh to Check if Disk Quota activated." );
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
	set_kb_item( name: "GSHB/quota/fstab", value: "error" );
	set_kb_item( name: "GSHB/quota/user", value: "error" );
	set_kb_item( name: "GSHB/quota/group", value: "error" );
	set_kb_item( name: "GSHB/quota/log", value: error );
	exit( 0 );
}
windowstest = ssh_cmd( socket: sock, cmd: "cmd /?" );
if(( ContainsString( windowstest, "windows" ) && ContainsString( windowstest, "interpreter" ) ) || ( ContainsString( windowstest, "Windows" ) && ContainsString( windowstest, "interpreter" ) )){
	set_kb_item( name: "GSHB/quota/fstab", value: "windows" );
	set_kb_item( name: "GSHB/quota/user", value: "windows" );
	set_kb_item( name: "GSHB/quota/group", value: "windows" );
	exit( 0 );
}
uname = get_kb_item( "ssh/login/uname" );
uname = ereg_replace( pattern: "\n", replace: "", string: uname );
if( !IsMatchRegexp( uname, "SunOS .*" ) ){
	fstab = ssh_cmd( socket: sock, cmd: "grep -v '^ *#' /etc/fstab" );
	aquotauser = ssh_cmd( socket: sock, cmd: "ls -lah /aquota.user" );
	aquotagroup = ssh_cmd( socket: sock, cmd: "ls -lah /aquota.group" );
	if(ContainsString( fstab, "grep: command not found" )){
		fstab = "nogrep";
	}
	if(ContainsString( aquotauser, "ls: command not found" )){
		aquotauser = "nols";
	}
	if(ContainsString( aquotauser, "ls: cannot access /aquota.user:" ) || ContainsString( aquotauser, "ls: Zugriff auf /aquota.user" )){
		aquotauser = "none";
	}
	if(ContainsString( aquotagroup, "ls: command not found" )){
		aquotagroup = "nols";
	}
	if(ContainsString( aquotagroup, "ls: cannot access /aquota.group:" ) || ContainsString( aquotagroup, "ls: Zugriff auf /aquota.group" )){
		aquotagroup = "none";
	}
	if(fstab != "nogrep"){
		fstabquota = egrep( string: fstab, pattern: "quota", icase: 0 );
	}
	if(!fstabquota || fstabquota == " "){
		fstabquota = "none";
	}
	set_kb_item( name: "GSHB/quota/fstab", value: fstabquota );
	set_kb_item( name: "GSHB/quota/user", value: aquotauser );
	set_kb_item( name: "GSHB/quota/group", value: aquotagroup );
}
else {
	if(IsMatchRegexp( uname, "SunOS .*" )){
		repquota = ssh_cmd( socket: sock, cmd: "LANG=C /usr/sbin/repquota -va" );
		zfsgetquota = ssh_cmd( socket: sock, cmd: "LANG=C /usr/sbin/zfs get quota" );
		if( IsMatchRegexp( repquota, ".*repquota: not found.*" ) ) {
			ufsquota = "norepquota";
		}
		else {
			if( IsMatchRegexp( repquota, "^quotactl: no quotas file.*" ) ) {
				ufsquota = "noquota";
			}
			else {
				ufsquota = repquota;
			}
		}
		if( IsMatchRegexp( zfsgetquota, ".*zfs: not found.*" ) ) {
			zfsquota = "nozfs";
		}
		else {
			Lst = split( buffer: zfsgetquota, keep: 0 );
			for(i = 1;i < max_index( Lst );i++){
				if( IsMatchRegexp( Lst[i], "^.*quota[ ]{5}(none|-).*" ) ) {
					continue;
				}
				else {
					if(IsMatchRegexp( Lst[i], "^.*quota.*" )){
						tmp = Lst[i];
					}
				}
				zfsquota += tmp + "\n";
			}
		}
		if(!zfsquota){
			zfsquota = "noquota";
		}
		set_kb_item( name: "GSHB/quota/uname", value: uname );
		set_kb_item( name: "GSHB/quota/zfsquota", value: zfsquota );
		set_kb_item( name: "GSHB/quota/ufsquota", value: ufsquota );
	}
}
exit( 0 );

