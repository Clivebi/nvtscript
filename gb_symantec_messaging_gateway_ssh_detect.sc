if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105719" );
	script_version( "$Revision: 11499 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-09-20 12:38:00 +0200 (Thu, 20 Sep 2018) $" );
	script_tag( name: "creation_date", value: "2016-05-17 12:36:46 +0200 (Tue, 17 May 2016)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Get Symantec Messaging Gateway Version via SSH." );
	script_tag( name: "qod_type", value: "package" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2016 Greenbone Networks GmbH" );
	script_family( "Service detection" );
	script_tag( name: "summary", value: "Get Symantec Messaging Gateway Version via SSH." );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/restricted_shell" );
	exit( 0 );
}
require("ssh_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
ret = ssh_cmd( socket: sock, cmd: "update notes", return_errors: TRUE, nosh: TRUE );
if(!ContainsString( ret, "Symantec Messaging Gateway" )){
	close( sock );
	exit( 0 );
}
vers = "unknown";
set_kb_item( name: "symantec_smg/detected", value: TRUE );
set_kb_item( name: "symantec_smg/ssh/detected", value: TRUE );
ret = ssh_cmd( socket: sock, cmd: "show -v", return_errors: TRUE, nosh: TRUE );
if(ContainsString( ret, "Version:" )){
	lines = split( buffer: ret, keep: FALSE );
	for line in lines {
		if(IsMatchRegexp( line, "^Version:" )){
			continue;
		}
		if(IsMatchRegexp( line, "^[0-9.-]+" )){
			version = eregmatch( pattern: "^([0-9.-]+)", string: line );
			if(!isnull( version[1] )){
				vers = version[1];
				if(ContainsString( vers, "-" )){
					_v = split( buffer: vers, sep: "-", keep: FALSE );
					vers = _v[0];
					patch = _v[1];
				}
			}
		}
		if(IsMatchRegexp( line, "patch-" )){
			p = eregmatch( pattern: "patch-[0-9.]+-([0-9]+)", string: line );
			if(!isnull( p[1] )){
				patch = p[1];
				break;
			}
		}
	}
}
if(vers){
	set_kb_item( name: "symantec_smg/ssh/version", value: vers );
}
if(patch){
	set_kb_item( name: "symantec_smg/ssh/patch", value: patch );
}
exit( 0 );

