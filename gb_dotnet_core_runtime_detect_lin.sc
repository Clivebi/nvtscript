if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815037" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2019-03-13 08:37:41 +0530 (Wed, 13 Mar 2019)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( ".NET Core Runtime Version Detection (Linux)" );
	script_tag( name: "summary", value: "Detects the installed version of
  .NET Core Runtime.

  The script logs in via ssh, searches for executable 'dotnet' and queries
  the found executables via command line option '--info'" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
paths = ssh_find_bin( prog_name: "dotnet", sock: sock );
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	runtimeop = ssh_cmd( socket: sock, cmd: bin + " --info", timeout: 60 );
	if(runtimeop){
		runname = eregmatch( pattern: ".NET Core runtimes installed:", string: runtimeop );
	}
	if(runname){
		runVer = eregmatch( pattern: "Version: ([0-9.]+)", string: runtimeop );
		if(runVer[1]){
			set_kb_item( name: "dotnet/core/runtime/Linux/Ver", value: runVer[1] );
			cpe = build_cpe( value: runVer[1], exp: "^([0-9.]+)", base: "cpe:/a:microsoft:.net_core:" );
			if(!cpe){
				cpe = "cpe:/a:microsoft:.net_core";
			}
			register_and_report_cpe( app: ".NET Core Runtime", ver: runVer[1], base: "cpe:/a:microsoft:.net_core:", expr: "^([0-9.]+)", insloc: bin, regService: "ssh-login", concluded: runVer[1] );
			ssh_close_connection();
		}
	}
}
ssh_close_connection();
exit( 0 );

