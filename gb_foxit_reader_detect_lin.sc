if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809332" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2016-11-08 17:20:13 +0530 (Tue, 08 Nov 2016)" );
	script_name( "Foxit Reader Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of
  Foxit Reader on Linux.

  The script logs in via ssh, searches for foxitreader and queries the
  version from 'FoxitReader' file." );
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
garg[0] = "-o";
garg[1] = "-m1";
garg[2] = "-a";
garg[3] = NASLString( "ReaderLite4Linux.*[0-9\\\\.\\\\+].*updater:" );
Foxit_Name = ssh_find_file( file_name: "/FoxitReader$", useregex: TRUE, sock: sock );
if(!Foxit_Name){
	ssh_close_connection();
	exit( 0 );
}
for binaryName in Foxit_Name {
	binaryName = chomp( binaryName );
	if(!binaryName){
		continue;
	}
	arg = garg[0] + " " + garg[1] + " " + garg[2] + " " + raw_string( 0x22 ) + garg[3] + raw_string( 0x22 ) + " " + binaryName;
	FoxitVer = ssh_get_bin_version( full_prog_name: "grep", version_argv: arg, ver_pattern: "", sock: sock );
	if(!FoxitVer[1]){
		continue;
	}
	FoxitVer = FoxitVer[1];
	FoxitVer = str_replace( find: raw_string( 0x00 ), replace: "", string: FoxitVer );
	FoxitVer = eregmatch( pattern: "ReaderLite4Linux([0-9.]+)", string: FoxitVer );
	if(FoxitVer[1]){
		set_kb_item( name: "foxit/reader/linux/ver", value: FoxitVer[1] );
		register_and_report_cpe( app: "Foxit Reader", ver: FoxitVer[1], base: "cpe:/a:foxitsoftware:reader:", expr: "([0-9.]+)", regPort: 0, insloc: binaryName, concluded: FoxitVer[0], regService: "ssh-login" );
		break;
	}
}
ssh_close_connection();
exit( 0 );

