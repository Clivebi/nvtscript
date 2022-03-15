if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800884" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2009-09-07 19:45:38 +0200 (Mon, 07 Sep 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Mozilla Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script is detects the installed version of Mozilla Browser." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "Mozilla Version Detection (Linux)";
mozilla_sock = ssh_login_or_reuse_connection();
if(!mozilla_sock){
	exit( 0 );
}
mozillaName = ssh_find_file( file_name: "/mozilla$", useregex: TRUE, sock: mozilla_sock );
for binary_name in mozillaName {
	binary_name = chomp( binary_name );
	if(!binary_name){
		continue;
	}
	mozillaVer = ssh_get_bin_version( full_prog_name: binary_name, sock: mozilla_sock, version_argv: "-v", ver_pattern: "Mozilla ([0-9]\\.[0-9.]+)(.*build ([0-9]+))?" );
	if(!isnull( mozillaVer[1] )){
		set_kb_item( name: "Mozilla/Linux/Ver", value: mozillaVer[1] );
		if(!isnull( mozillaVer[3] )){
			ver = mozillaVer[1] + "." + mozillaVer[3];
			set_kb_item( name: "Mozilla/Build/Linux/Ver", value: ver );
			log_message( data: "Mozilla version " + ver + " running at location " + binary_name + " was detected on the host" );
			cpe = build_cpe( value: ver, exp: "^([0-9.]+)", base: "cpe:/a:mozilla:mozilla:" );
			if(!isnull( cpe )){
				register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
			}
		}
	}
}
ssh_close_connection();

