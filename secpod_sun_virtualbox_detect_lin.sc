if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901051" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Oracle VirtualBox Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detection of installed versions of Sun/Oracle VirtualBox,
a hypervisor tool, on Linux systems.

The script logs in via ssh, searches for executables of VirtualBox and
queries the found executables via command line option '--version'." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("version_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
getPath = ssh_find_bin( prog_name: "VBoxManage", sock: sock );
for executableFile in getPath {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	vbVer = ssh_get_bin_version( full_prog_name: executableFile, sock: sock, version_argv: "--version", ver_pattern: "([0-9.]+([a-z0-9]+)?)" );
	if(vbVer[1] != NULL){
		Ver = ereg_replace( pattern: "([a-z])", string: vbVer[1], replace: "." );
		if(Ver){
			set_kb_item( name: "Sun/VirtualBox/Lin/Ver", value: Ver );
			if( version_is_less( version: Ver, test_version: "3.2.0" ) ){
				register_and_report_cpe( app: "Oracle/Sun Virtual Box", ver: Ver, concluded: Ver, base: "cpe:/a:sun:virtualbox:", expr: "^(3\\..*)", insloc: executableFile );
				register_and_report_cpe( app: "Oracle/Sun Virtual Box", ver: Ver, concluded: Ver, base: "cpe:/a:sun:xvm_virtualbox:", expr: "^([0-2]\\..*)", insloc: executableFile );
			}
			else {
				register_and_report_cpe( app: "Oracle/Sun Virtual Box", ver: Ver, concluded: Ver, base: "cpe:/a:oracle:vm_virtualbox:", expr: "^([3-9]\\..*)", insloc: executableFile );
			}
		}
	}
}
ssh_close_connection();

