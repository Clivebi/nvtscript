if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900387" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-06-30 16:55:49 +0200 (Tue, 30 Jun 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Openswan Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of Openswan." );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("ssh_func.inc.sc");
SCRIPT_DESC = "Openswan Version Detection";
oswan_sock = ssh_login_or_reuse_connection();
if(!oswan_sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "ipsec", sock: oswan_sock );
for swanBin in paths {
	swanBin = chomp( swanBin );
	if(!swanBin){
		continue;
	}
	oswanVer = ssh_get_bin_version( full_prog_name: swanBin, sock: oswan_sock, version_argv: "--version", ver_pattern: "Openswan U(([0-9.]+)(rc[0-9])?)" );
	if(oswanVer[1] != NULL){
		set_kb_item( name: "Openswan_or_StrongSwan/Lin/Installed", value: TRUE );
		set_kb_item( name: "Openswan/Ver", value: oswanVer[1] );
		log_message( data: "Openswan version " + oswanVer[1] + " was detected on the host" );
		ssh_close_connection();
		cpe = build_cpe( value: oswanVer[1], exp: "^([0-9.]+)(rc[0-9])?", base: "cpe:/a:openswan:openswan:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
ssh_close_connection();

