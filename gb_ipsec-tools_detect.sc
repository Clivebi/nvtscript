if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800707" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2009-05-13 10:01:19 +0200 (Wed, 13 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "IPSec Tools Version Detection" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "The script detects the version of IPSec Tools for Linux on
  remote host and sets the result into KB." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "IPSec Tools Version Detection";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
ipsecPaths = ssh_find_file( file_name: "/setkey$", useregex: TRUE, sock: sock );
for ipsecBin in ipsecPaths {
	ipsecBin = chomp( ipsecBin );
	if(!ipsecBin){
		continue;
	}
	ipsecVer = ssh_get_bin_version( full_prog_name: ipsecBin, sock: sock, version_argv: "-V", ver_pattern: "ipsec-tools ([0-9.]+)" );
	if(ipsecVer[1] != NULL){
		set_kb_item( name: "IPSec/Tools/Ver", value: ipsecVer[1] );
		log_message( data: " IPSec Tools version " + ipsecVer[1] + " was detected on the host" );
		ssh_close_connection();
		cpe = build_cpe( value: ipsecVer[1], exp: "^([0-9.]+)", base: "cpe:/a:ipsec-tools:ipsec-tools:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
ssh_close_connection();

