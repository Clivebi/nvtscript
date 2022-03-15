if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800964" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2009-11-04 07:03:36 +0100 (Wed, 04 Nov 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SquidGuard Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of SquidGuard." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "SquidGuard Version Detection";
sgSock = ssh_login_or_reuse_connection();
if(!sgSock){
	exit( 0 );
}
getPath = ssh_find_bin( prog_name: "squidGuard", sock: sgSock );
for binFile in getPath {
	binFile = chomp( binFile );
	if(!binFile){
		continue;
	}
	sgVer = ssh_get_bin_version( full_prog_name: binFile, sock: sgSock, version_argv: "-v", ver_pattern: "SquidGuard.? ([0-9.]+)([a-z][0-9])?" );
	if(sgVer[1] != NULL){
		if( IsMatchRegexp( sgVer[2], "^[a-z][0-9]" ) ){
			sgVer = sgVer[1] + "." + sgVer[2];
		}
		else {
			sgVer = sgVer[1];
		}
		set_kb_item( name: "SquidGuard/Ver", value: sgVer );
		log_message( data: "squidGuard version " + sgVer + " running at location " + binFile + " was detected on the host" );
		cpe = build_cpe( value: sgVer, exp: "^([0-9.]+)", base: "cpe:/a:squidguard:squidguard:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}
ssh_close_connection();

