if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900189" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-01-22 12:00:13 +0100 (Thu, 22 Jan 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "NASL Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of NASL." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "NASL Version Detection (Linux)";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_file( file_name: "/nasl$", useregex: TRUE, sock: sock );
for naslBin in paths {
	naslBin = chomp( naslBin );
	if(!naslBin){
		continue;
	}
	naslVer = ssh_get_bin_version( full_prog_name: naslBin, sock: sock, version_argv: "-version", ver_pattern: "nasl ([0-9.a-z]+)" );
	if(naslVer[1] != NULL){
		set_kb_item( name: "NASL/Linux/Ver", value: naslVer[1] );
		log_message( data: "NASL version " + naslVer[1] + " running at location " + naslBin + " was detected on the host" );
		ssh_close_connection();
		cpe = build_cpe( value: naslVer[1], exp: "^([0-9.]+)", base: "cpe:/a:nessus:nessus:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
ssh_close_connection();

