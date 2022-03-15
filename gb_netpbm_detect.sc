if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800470" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Netpbm Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "The script detects the installed version of Netpbm." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
modName = ssh_find_file( file_name: "/libnetpbm\\.so$", useregex: TRUE, sock: sock );
if(!modName){
	ssh_close_connection();
	exit( 0 );
}
garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = NASLString( "Netpbm [0-9.].\\\\+" );
for binaryName in modName {
	binaryName = chomp( binaryName );
	if(!binaryName){
		continue;
	}
	arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string( 0x22 ) + garg[3] + raw_string( 0x22 ) + " " + binaryName;
	netpbmVer = ssh_get_bin_version( full_prog_name: "grep", version_argv: arg, ver_pattern: "Netpbm ([0-9.]{3,})", sock: sock );
	if(netpbmVer[1]){
		set_kb_item( name: "NetPBM/Ver", value: netpbmVer[1] );
		register_and_report_cpe( app: "NetPBM", ver: netpbmVer[1], base: "cpe:/a:netpbm:netpbm:", expr: "([0-9.]+)", regPort: 0, insloc: binaryName, concluded: netpbmVer[0], regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

