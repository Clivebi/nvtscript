if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900506" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-02-20 17:40:17 +0100 (Fri, 20 Feb 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "ProFTPD Server Version Detection (Local)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "secpod_proftpd_server_remote_detect.sc", "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of ProFTPD Server." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("ssh_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
ftpPaths = ssh_find_file( file_name: "/proftpd$", useregex: TRUE, sock: sock );
if(!ftpPaths){
	ssh_close_connection();
	exit( 0 );
}
for binPath in ftpPaths {
	binPath = chomp( binPath );
	if(!binPath){
		continue;
	}
	ftpVer = ssh_get_bin_version( full_prog_name: binPath, version_argv: "-v", ver_pattern: "ProFTPD Version ([0-9.a-z]+)", sock: sock );
	ftpVer = eregmatch( pattern: "Version ([0-9.]+)(rc[0-9])?", string: ftpVer[0] );
	if(!isnull( ftpVer[1] )){
		if( !isnull( ftpVer[2] ) ) {
			ftpVer = ftpVer[1] + "." + ftpVer[2];
		}
		else {
			ftpVer = ftpVer[1];
		}
		if(ftpVer){
			set_kb_item( name: "ProFTPD/Ver", value: ftpVer );
			set_kb_item( name: "ProFTPD/Installed", value: TRUE );
			cpe = build_cpe( value: ftpVer, exp: "^([0-9.]+)(rc[0-9]+)?", base: "cpe:/a:proftpd:proftpd:" );
			if(!cpe){
				cpe = "cpe:/a:proftpd:proftpd";
			}
			register_product( cpe: cpe, location: binPath, port: 0, service: "ssh-login" );
			log_message( data: build_detection_report( app: "ProFTPD", version: ftpVer, install: binPath, cpe: cpe, concluded: ftpVer ), port: 0 );
		}
	}
}
exit( 0 );

