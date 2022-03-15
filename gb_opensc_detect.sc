if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800369" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2009-03-16 10:38:04 +0100 (Mon, 16 Mar 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "OpenSC Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of OpenSC on the host." );
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
openscName = ssh_find_file( file_name: "/opensc-config$", useregex: TRUE, sock: sock );
if(!openscName){
	ssh_close_connection();
	exit( 0 );
}
for binName in openscName {
	binName = chomp( binName );
	if(!binName){
		continue;
	}
	openscVer = ssh_get_bin_version( full_prog_name: binName, ver_pattern: "([0-9.]{3,})", version_argv: "--version", sock: sock );
	if(openscVer[0]){
		version = openscVer[1];
		set_kb_item( name: "opensc/detected", value: TRUE );
		set_kb_item( name: "opensc/ssh/detected", value: TRUE );
		register_and_report_cpe( app: "OpenSC", ver: version, base: "cpe:/a:opensc-project:opensc:", expr: "([0-9.]+)", regPort: 0, insloc: binName, concluded: openscVer[0], regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

