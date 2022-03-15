if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900827" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-27 13:43:20 +0200 (Thu, 27 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "WebDAV Neon Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of WebDAV Neon." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "WebDAV Neon Version Detection";
neon_sock = ssh_login_or_reuse_connection();
if(!neon_sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/neon-config$", useregex: TRUE, sock: neon_sock );
for binName in paths {
	binName = chomp( binName );
	if(!binName){
		continue;
	}
	neonVer = ssh_get_bin_version( full_prog_name: binName, sock: neon_sock, version_argv: "--version", ver_pattern: "neon ([0-9]+\\.[0-9]+\\.[0-9]+)" );
	if(neonVer[1] != NULL){
		set_kb_item( name: "WebDAV/Neon/Ver", value: neonVer[1] );
		log_message( data: "WebDAV Neon version " + neonVer[1] + " was detected on the host" );
		ssh_close_connection();
		cpe = build_cpe( value: neonVer[1], exp: "^([0-9.]+)", base: "cpe:/a:webdav:neon:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
ssh_close_connection();

