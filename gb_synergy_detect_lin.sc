if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801874" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2011-04-22 16:38:12 +0200 (Fri, 22 Apr 2011)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "Synergy Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script finds the installed Synergy version." );
	exit( 0 );
}
require("cpe.inc.sc");
require("ssh_func.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
paths = ssh_find_bin( prog_name: "synergys", sock: sock );
for bin in paths {
	bin = chomp( bin );
	if(!bin){
		continue;
	}
	synVer = ssh_get_bin_version( full_prog_name: bin, sock: sock, version_argv: "--version", ver_pattern: "synergys ([0-9.]+)" );
	if(!isnull( synVer[1] )){
		set_kb_item( name: "Synergy/Lin/Ver", value: synVer[1] );
		cpe = build_cpe( value: synVer[1], exp: "^([0-9.]+)", base: "cpe:/a:synergy-foss:synergy:" );
		if(!cpe){
			cpe = "cpe:/a:synergy-foss:synergy";
		}
		register_product( cpe: cpe, location: bin, service: "ssh-login" );
		log_message( data: build_detection_report( app: "Synergy", version: synVer[1], install: bin, cpe: cpe, concluded: synVer[0] ) );
	}
}
ssh_close_connection();
exit( 0 );

