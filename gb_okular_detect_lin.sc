if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112806" );
	script_version( "2020-08-12T09:05:13+0000" );
	script_tag( name: "last_modification", value: "2020-08-12 09:05:13 +0000 (Wed, 12 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-11 11:31:24 +0000 (Tue, 11 Aug 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Okular Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH based detection of Okular." );
	script_xref( name: "URL", value: "https://okular.kde.org/" );
	exit( 0 );
}
CPE = "cpe:/a:kde:okular:";
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = make_list();
for file in make_list( "okular" ) {
	_paths = ssh_find_bin( prog_name: file, sock: sock );
	if(_paths){
		paths = nasl_make_list_unique( paths, _paths );
	}
}
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	ver = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "--version", ver_pattern: "Okular: ([0-9.]+)" );
	if(!isnull( ver[1] )){
		version = ver[1];
		set_kb_item( name: "kde/okular/detected", value: TRUE );
		register_and_report_cpe( app: "Okular", ver: version, concluded: ver[0], base: CPE, expr: "([0-9.]+)", insloc: bin, regPort: 0, regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

