if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801972" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2011-09-13 07:51:43 +0200 (Tue, 13 Sep 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Tcptrack Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script finds the Tcptrack installed version." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Tcptrack Version Detection";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
tcptName = ssh_find_file( file_name: "/tcptrack$", useregex: TRUE, sock: sock );
if(tcptName){
	for binaryName in tcptName {
		binaryName = chomp( binaryName );
		if(!binaryName){
			continue;
		}
		tcptVer = ssh_get_bin_version( full_prog_name: binaryName, version_argv: "-v", ver_pattern: "tcptrack v([0-9.]+)", sock: sock );
		if(tcptVer){
			set_kb_item( name: "Tcptrack/Ver", value: tcptVer[1] );
			log_message( data: "Tcptrack version " + tcptVer[1] + " installed at location " + binaryName + " was detected on the host" );
			cpe = build_cpe( value: tcptVer[1], exp: "^([0-9.]+)", base: "cpe:/a:rhythm:tcptrack:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
			ssh_close_connection();
		}
	}
	ssh_close_connection();
}
close( sock );

