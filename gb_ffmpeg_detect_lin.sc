if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800467" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2010-02-17 08:26:50 +0100 (Wed, 17 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "FFmpeg Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of FFmpeg." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "ffmpeg", sock: sock );
for ffmpegbin in paths {
	ffmpegbin = chomp( ffmpegbin );
	if(!ffmpegbin){
		continue;
	}
	ffmpegVer = ssh_get_bin_version( full_prog_name: ffmpegbin, sock: sock, version_argv: "--version", ver_pattern: "version ([0-9.]+)" );
	if(ffmpegVer[1] != NULL){
		set_kb_item( name: "FFmpeg/Linux/Ver", value: ffmpegVer[1] );
		ssh_close_connection();
		register_and_report_cpe( app: "FFmpeg", ver: ffmpegVer[1], base: "cpe:/a:ffmpeg:ffmpeg:", expr: "^([0-9.]+)", insloc: ffmpegbin );
		exit( 0 );
	}
}
ssh_close_connection();

