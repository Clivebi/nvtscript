if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800450" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2010-02-04 12:53:38 +0100 (Thu, 04 Feb 2010)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "GZip Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Checks whether GZip is present on
  the target system and if so, tries to figure out the installed version." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
binaries = ssh_find_bin( prog_name: "gzip", sock: sock );
for binary in binaries {
	binary = chomp( binary );
	if(!binary){
		continue;
	}
	vers = ssh_get_bin_version( full_prog_name: binary, sock: sock, version_argv: "--version", ver_pattern: "gzip ([0-9.]{2,})" );
	if(!isnull( vers[1] )){
		set_kb_item( name: "gzip/detected", value: TRUE );
		cpe = build_cpe( value: vers[1], exp: "^([0-9.]+)", base: "cpe:/a:gnu:gzip:" );
		if(!cpe){
			cpe = "cpe:/a:gnu:gzip";
		}
		register_product( cpe: cpe, port: 0, location: binary, service: "ssh-login" );
		report = build_detection_report( app: "GZip", version: vers[1], install: binary, cpe: cpe, concluded: vers[max_index( vers ) - 1] );
		log_message( port: 0, data: report );
	}
}
ssh_close_connection();
exit( 0 );

