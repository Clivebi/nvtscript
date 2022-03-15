if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801438" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2010-08-19 10:23:11 +0200 (Thu, 19 Aug 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "SWFTools Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script finds the installed SWFTools version." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "SWFTools Version Detection";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
swfName = ssh_find_file( file_name: "/swfdump$", useregex: TRUE, sock: sock );
for binaryName in swfName {
	binaryName = chomp( binaryName );
	if(!binaryName){
		continue;
	}
	swfVer = ssh_get_bin_version( full_prog_name: binaryName, sock: sock, version_argv: "-V", ver_pattern: "swftools ([0-9.]+)" );
	if(swfVer[1]){
		set_kb_item( name: "SWFTools/Ver", value: swfVer[1] );
		log_message( data: "SWFTools version " + swfVer[1] + " running at location " + binaryName + " was detected on the host" );
		cpe = build_cpe( value: swfVer[1], exp: "^([0-9.]+)", base: "cpe:/a:swftools:swftools:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}
close( sock );
ssh_close_connection();

