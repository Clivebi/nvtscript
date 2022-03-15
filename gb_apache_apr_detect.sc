if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800680" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2009-08-17 14:35:19 +0200 (Mon, 17 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Apache APR Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of Apache APR." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Apache APR Version Detection";
apr_sock = ssh_login_or_reuse_connection();
if(!apr_sock){
	exit( 0 );
}
for path in make_list( "apr-config",
	 "apr-1-config" ) {
	getPath = ssh_find_bin( prog_name: path, sock: apr_sock );
	for binaryFile in getPath {
		binaryFile = chomp( binaryFile );
		if(!binaryFile){
			continue;
		}
		aprVer = ssh_get_bin_version( full_prog_name: binaryFile, sock: apr_sock, version_argv: "--version", ver_pattern: "[0-9.]+" );
		if(aprVer[0] != NULL){
			set_kb_item( name: "Apache/APR_or_Utils/Installed", value: TRUE );
			set_kb_item( name: "Apache/APR/Ver", value: aprVer[0] );
			log_message( data: "Apache APR version " + aprVer[0] + " running at location " + binaryFile + " was detected on the host" );
			cpe = build_cpe( value: aprVer[0], exp: "^([0-9.]+)", base: "cpe:/a:apache:portable_runtime:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}
ssh_close_connection();

