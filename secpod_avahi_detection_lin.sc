if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900416" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2008-12-31 15:14:17 +0100 (Wed, 31 Dec 2008)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Avahi Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of Avahi Daemon.

  The script logs in via ssh, searches for executable 'avahi-daemon' and
  queries the found executables via command line option '--version'." );
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
avahiName = ssh_find_file( file_name: "/avahi-daemon$", useregex: TRUE, sock: sock );
for executableFile in avahiName {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	avahiVer = ssh_get_bin_version( full_prog_name: executableFile, version_argv: "--version", ver_pattern: "avahi-daemon [0-9.]+", sock: sock );
	if(avahiVer[0]){
		version = "unknown";
		vers = eregmatch( string: avahiVer[0], pattern: "avahi-daemon ([0-9.]+)" );
		if(vers[1]){
			version = vers[1];
		}
		set_kb_item( name: "Avahi/Linux/Ver", value: version );
		set_kb_item( name: "avahi-daemon/detected", value: TRUE );
		register_and_report_cpe( app: "Avahi", ver: version, base: "cpe:/a:avahi:avahi:", expr: "^([0-9.]+)", regPort: 0, insloc: executableFile, concluded: avahiVer[0], regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

