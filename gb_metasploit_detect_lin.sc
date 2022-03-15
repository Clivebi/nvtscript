if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811588" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2017-08-30 17:46:40 +0530 (Wed, 30 Aug 2017)" );
	script_name( "Metasploit Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detects the installed version of
  Metasploit on Linux.

  The script logs in via ssh, searches for executable and queries the
  version from 'version.yml' file." );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
if(!paths = ssh_find_file( file_name: "/version\\.yml$", useregex: TRUE, sock: sock )){
	exit( 0 );
}
for executableFile in paths {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	if(ContainsString( executableFile, "metasploit" )){
		metVer = ssh_get_bin_version( full_prog_name: "cat", version_argv: executableFile, ver_pattern: "version: ([0-9.]+)", sock: sock );
		metUpdate = ssh_get_bin_version( full_prog_name: "cat", version_argv: executableFile, ver_pattern: "revision: '([0-9]+)'", sock: sock );
		if(metVer[1] != NULL){
			set_kb_item( name: "Metasploit/Linux/Ver", value: metVer[1] );
			if(metUpdate[1] != NULL){
				set_kb_item( name: "Metasploit/Linux/VerUpdate", value: metUpdate[1] );
			}
			cpe = build_cpe( value: metVer[1], exp: "^([0-9.]+)", base: "cpe:/a:rapid7:metasploit:" );
			if(!cpe){
				cpe = "cpe:/a:rapid7:metasploit";
			}
			register_product( cpe: cpe, location: executableFile );
			log_message( data: build_detection_report( app: "Metasploit", version: metVer[1], install: executableFile, cpe: cpe, concluded: metVer[1] ) );
			exit( 0 );
		}
	}
}
ssh_close_connection();

