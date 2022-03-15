if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900714" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-29 07:35:11 +0200 (Fri, 29 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Transmission Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "The script is detects the installed version of Transmission
  for Linux." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Transmission Version Detection";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
transPaths = ssh_find_file( file_name: "/transmissioncli$", useregex: TRUE, sock: sock );
for transBin in transPaths {
	transBin = chomp( transBin );
	if(!transBin){
		continue;
	}
	transVer = ssh_get_bin_version( full_prog_name: transBin, sock: sock, version_argv: "-v", ver_pattern: "Transmission ([0-9.]+)" );
	if(transVer[1] != NULL){
		set_kb_item( name: "Transmission/Ver", value: transVer[1] );
		log_message( data: "Transmission version " + transVer[1] + " running at location " + transBin + " was detected on the host" );
		ssh_close_connection();
		cpe = build_cpe( value: transVer[1], exp: "^([0-9.]+)", base: "cpe:/a:transmissionbt:transmission:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
ssh_close_connection();

