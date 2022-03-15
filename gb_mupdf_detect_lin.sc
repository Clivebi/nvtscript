if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112804" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2020-08-11 07:56:12 +0000 (Tue, 11 Aug 2020)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "MuPDF Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "SSH based detection of MuPDF." );
	script_xref( name: "URL", value: "https://mupdf.com/" );
	exit( 0 );
}
CPE = "cpe:/a:artifex:mupdf:";
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = make_list();
for file in make_list( "mupdf",
	 "mupdf-x11",
	 "mupdf-gl" ) {
	_paths = ssh_find_file( file_name: file + "$", useregex: TRUE, sock: sock );
	if(_paths){
		paths = nasl_make_list_unique( paths, _paths );
	}
}
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	bin_check = ssh_cmd( socket: sock, cmd: bin + " -0" );
	if(egrep( pattern: "^usage: mupdf", string: bin_check )){
		set_kb_item( name: "artifex/mupdf/detected", value: TRUE );
		version = "unknown";
		concl = chomp( bin_check );
		if(vers_grep = ssh_get_bin_version( full_prog_name: "strings", version_argv: bin, ver_pattern: "MuPDF ([0-9.a]+)", sock: sock )){
			if(vers_grep[1]){
				version = vers_grep[1];
				concl = vers_grep[0] + " from binary version extraction via: strings " + bin + " | egrep 'MuPDF ([0-9.a]+)'";
			}
		}
		register_and_report_cpe( app: "MuPDF", ver: version, concluded: concl, base: CPE, expr: "([0-9.a]+)", insloc: bin, regPort: 0, regService: "ssh-login" );
	}
}
ssh_close_connection();
exit( 0 );

