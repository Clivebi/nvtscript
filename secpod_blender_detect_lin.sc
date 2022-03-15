if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900251" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Blender Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of Blender." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Blender Version Detection (Linux)";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
blendPath = ssh_find_file( file_name: "/blender$", useregex: TRUE, sock: sock );
for binPath in blendPath {
	binPath = chomp( binPath );
	if(!binPath){
		continue;
	}
	blendVer = ssh_get_bin_version( full_prog_name: binPath, version_argv: "--version", ver_pattern: "Blender ([0-9.]+)( .sub [0-9]+)?", sock: sock );
	if(blendVer[1] != NULL){
		if( ContainsString( blendVer[2], "sub" ) ){
			blendVer[2] = ereg_replace( pattern: " \\(sub ", string: blendVer[2], replace: "" );
			blendVer = blendVer[1] + "." + blendVer[2];
		}
		else {
			blendVer = blendVer[1];
		}
		set_kb_item( name: "Blender/Lin/Ver", value: blendVer );
		log_message( data: "Blender version " + blendVer + " running at location " + binPath + " was detected on the host" );
		cpe = build_cpe( value: blendVer, exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:blender:blender:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}
ssh_close_connection();

