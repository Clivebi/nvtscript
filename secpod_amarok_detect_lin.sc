if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900430" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Amarok Player Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "The script detects the version of Amarok Player for Linux on
  remote host and sets the result into KB." );
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
amarokPaths = ssh_find_file( file_name: "/amarok$", useregex: TRUE, sock: sock );
for amarokBin in amarokPaths {
	amarokBin = chomp( amarokBin );
	if(!amarokBin){
		continue;
	}
	amarokVer = ssh_get_bin_version( full_prog_name: amarokBin, sock: sock, version_argv: "-v", ver_pattern: "Amarok: ([0-9]\\.[0-9]+)" );
	if(amarokVer[1]){
		set_kb_item( name: "Amarok/Linux/Ver", value: amarokVer[1] );
		set_kb_item( name: "amarok/detected", value: TRUE );
		register_and_report_cpe( app: "Amarok Player", ver: amarokVer[1], base: "cpe:/a:amarok:amarok:", expr: "^([0-9.]+)", regPort: 0, insloc: amarokBin, concluded: amarokVer[0], regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

