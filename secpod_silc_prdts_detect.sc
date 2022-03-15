if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900950" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SILC Products Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of SILC Products." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "SILC Products Version Detection";
silc_sock = ssh_login_or_reuse_connection();
if(!silc_sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/silc$", useregex: TRUE, sock: silc_sock );
for clntBin in paths {
	clntBin = chomp( clntBin );
	if(!clntBin){
		continue;
	}
	clntVer = ssh_get_bin_version( full_prog_name: clntBin, sock: silc_sock, version_argv: "--version", ver_pattern: "Client ([0-9.]+)" );
	if(clntVer[1] != NULL){
		set_kb_item( name: "SILC/Client/Ver", value: clntVer[1] );
		log_message( data: "SILC version " + clntVer[1] + " running at location " + clntBin + " was detected on the host" );
		cpe = build_cpe( value: clntVer[1], exp: "^([0-9.]+)", base: "cpe:/a:silcnet:silc_client:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}
ssh_close_connection();

