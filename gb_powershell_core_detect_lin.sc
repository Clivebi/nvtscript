if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812746" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2018-01-31 10:53:40 +0530 (Wed, 31 Jan 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "PowerShell Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detects the installed version of PowerShell.

  The script logs in via ssh, searches for executable 'pwsh' and queries the
  found executables via command line option '-v'" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
list = make_list( "pwsh-preview",
	 "pwsh" );
for pgm in list {
	paths = ssh_find_bin( prog_name: pgm, sock: sock );
	for bin in paths {
		bin = chomp( bin );
		if(!bin){
			continue;
		}
		psVer = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "-v", ver_pattern: "PowerShell v?([0-9a-z.-]+)" );
		if(psVer[1]){
			psVer = ereg_replace( pattern: "-preview", string: psVer[1], replace: "" );
			set_kb_item( name: "PowerShell/Linux/Ver", value: psVer );
			cpe = build_cpe( value: psVer, exp: "^([0-9rc.-]+)", base: "cpe:/a:microsoft:powershell:" );
			if(!cpe){
				cpe = "cpe:/a:microsoft:powershell";
			}
			register_product( cpe: cpe, location: bin, service: "ssh-login" );
			log_message( data: build_detection_report( app: "PowerShell", version: psVer, install: bin, cpe: cpe, concluded: psVer ) );
		}
	}
}
ssh_close_connection();
exit( 0 );

