if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800832" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2009-07-15 13:05:34 +0200 (Wed, 15 Jul 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Gizmo5 Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "The script is detects the installed version of Gizmo5." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
gizmo_sock = ssh_login_or_reuse_connection();
if(!gizmo_sock){
	exit( 0 );
}
garg[0] = "-o";
garg[1] = "-m2";
garg[2] = "-a";
garg[3] = NASLString( "[0-9]\\\\+\\\\.[0-9]\\\\+\\\\.[0-9]\\\\+\\\\.[0-9]\\\\+" );
gizmoName = ssh_find_bin( prog_name: "gizmo", sock: gizmo_sock );
if(!gizmoName){
	ssh_close_connection();
	exit( 0 );
}
for binaryName in gizmoName {
	binaryName = chomp( binaryName );
	if(!binaryName){
		continue;
	}
	arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string( 0x22 ) + garg[3] + raw_string( 0x22 ) + " " + binaryName;
	gizmoVer = ssh_get_bin_version( full_prog_name: "grep", version_argv: arg, sock: gizmo_sock, ver_pattern: "([0-9]\\.[0-9]\\.[0-9]\\.[0-9][0-9]?)" );
	if(gizmoVer[1]){
		set_kb_item( name: "Gizmo5/Linux/Ver", value: gizmoVer[1] );
		register_and_report_cpe( app: "Gizmo5", ver: gizmoVer[1], base: "cpe:/a:gizmo5:gizmo:", expr: "([0-9.]+)", regPort: 0, insloc: binaryName, concluded: gizmoVer[0], regService: "ssh-login" );
		break;
	}
}
ssh_close_connection();
exit( 0 );

