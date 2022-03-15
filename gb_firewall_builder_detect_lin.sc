if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800995" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2010-03-18 15:44:57 +0100 (Thu, 18 Mar 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Firewall Builder Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of Firewall Builder." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Firewall Builder Version Detection (Linux)";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "fwbuilder", sock: sock );
for fwbuildbin in paths {
	fwbuildbin = chomp( fwbuildbin );
	if(!fwbuildbin){
		continue;
	}
	fwbuildVer = ssh_get_bin_version( full_prog_name: fwbuildbin, sock: sock, version_argv: "-v", ver_pattern: "([0-9.]+)" );
	if(fwbuildVer[1] != NULL){
		set_kb_item( name: "FirewallBuilder/Linux/Ver", value: fwbuildVer[1] );
		log_message( data: "Firewall Builder version " + fwbuildVer[1] + " running at location " + fwbuildbin + " was detected on the host" );
		cpe = build_cpe( value: fwbuildVer[1], exp: "^([0-9.]+)", base: "cpe:/a:fwbuilder:firewall_builder:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
	}
}
ssh_close_connection();

