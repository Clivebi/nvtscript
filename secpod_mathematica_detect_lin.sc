if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901118" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2010-06-01 15:40:11 +0200 (Tue, 01 Jun 2010)" );
	script_name( "Mathematica Version Detection (Linux)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script finds the installed Mathematica version." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Mathematica Version Detection (Linux)";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/\\.VersionID$", useregex: TRUE, sock: sock );
if(paths != NULL){
	for path in paths {
		path = chomp( path );
		if(!path){
			continue;
		}
		if(ContainsString( path, "Mathematica" )){
			mPath = ereg_replace( pattern: " ", replace: "\\ ", string: path );
			mVer = ssh_get_bin_version( full_prog_name: "cat", version_argv: mPath, ver_pattern: "([0-9.]+)", sock: sock );
			if(mVer[1] != NULL){
				set_kb_item( name: "Mathematica/Ver", value: mVer[1] );
				log_message( data: "Mathematica version " + mVer[1] + " running at location " + path + " was detected on the host" );
				cpe = build_cpe( value: mVer[1], exp: "^([0-9.]+)", base: "cpe:/a:wolfram_research:mathematica:" );
				if(!isnull( cpe )){
					register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
				}
			}
		}
	}
}
close( sock );
ssh_close_connection();

