if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800324" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2009-01-13 15:40:34 +0100 (Tue, 13 Jan 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "F-PROT Antivirus Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "The script finds the installed F-PROT Antivirus Version." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "F-PROT Antivirus Version Detection (Linux)";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
binPaths = ssh_find_file( file_name: "/fpscan$", useregex: TRUE, sock: sock );
for fprotBin in binPaths {
	fprotBin = chomp( fprotBin );
	if(!fprotBin){
		continue;
	}
	fprotVer = ssh_get_bin_version( full_prog_name: fprotBin, sock: sock, version_argv: "--version", ver_pattern: "Antivirus version ([0-9.]+)" );
	if(fprotVer[1] != NULL){
		set_kb_item( name: "F-Prot/AV/Linux/Ver", value: fprotVer[1] );
		log_message( data: "F-Prot Anti Virus version " + fprotVer[1] + " running at location " + fprotBin + " was detected on the host" );
		ssh_close_connection();
		cpe = build_cpe( value: fprotVer[1], exp: "^([0-9.]+)", base: "cpe:/a:f-prot:f-prot_antivirus:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
ssh_close_connection();

