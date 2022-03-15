if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113357" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2019-03-20 11:13:44 +0100 (Wed, 20 Mar 2019)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "rdesktop Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects whether rdesktop is present on the
  target system and if so, tries to figure out the installed version." );
	script_xref( name: "URL", value: "https://www.rdesktop.org/" );
	exit( 0 );
}
CPE = "cpe:/a:rdesktop:rdesktop:";
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "rdesktop", sock: sock );
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	ver = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "--version", ver_pattern: "Version ([0-9.]+)" );
	if(!isnull( ver[1] )){
		set_kb_item( name: "rdesktop/detected", value: TRUE );
		ssh_close_connection();
		register_and_report_cpe( app: "rdesktop", ver: ver[1], base: CPE, expr: "^([0-9.]+)", concluded: ver[0], regPort: 0, regService: "ssh-login", insloc: bin );
	}
}
ssh_close_connection();
exit( 0 );

