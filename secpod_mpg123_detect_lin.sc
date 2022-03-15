if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900543" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-04-28 07:58:48 +0200 (Tue, 28 Apr 2009)" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "mpg123 Player Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of mpg123 Player." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "mpg123 Player Version Detection (Linux)";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/mpg123$", useregex: TRUE, sock: sock );
if(!paths){
	ssh_close_connection();
	exit( 0 );
}
for binName in paths {
	binName = chomp( binName );
	if(!binName){
		continue;
	}
	mpgVer = ssh_get_bin_version( full_prog_name: binName, version_argv: "--version", ver_pattern: "[0-9.]{3,}", sock: sock );
	if(!isnull( mpgVer[0] )){
		set_kb_item( name: "mpg123/Linux/Ver", value: mpgVer[0] );
		log_message( data: "mpg123 Player version " + mpgVer[0] + " running at location " + binName + " was detected on the host" );
		ssh_close_connection();
		cpe = build_cpe( value: mpgVer[0], exp: "^([0-9.]+)", base: "cpe:/a:mpg123:mpg123:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
ssh_close_connection();

