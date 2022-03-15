if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800923" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2009-08-11 07:36:16 +0200 (Tue, 11 Aug 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Django Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script detects the installed version of Django." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
getPath = ssh_find_file( file_name: "/django-admin\\.py$", useregex: TRUE, sock: sock );
for binaryFile in getPath {
	binaryFile = chomp( binaryFile );
	if(!binaryFile){
		continue;
	}
	djangoVer = ssh_get_bin_version( full_prog_name: binaryFile, sock: sock, version_argv: "--version", ver_pattern: "^[0-9.]{3,}" );
	if(djangoVer[0]){
		set_kb_item( name: "Django/Linux/Ver", value: djangoVer[0] );
		cpe = build_cpe( value: djangoVer[0], exp: "^([0-9.]+)", base: "cpe:/a:djangoproject:django:" );
		if(!cpe){
			cpe = "cpe:/a:djangoproject:django";
		}
		register_product( cpe: cpe, location: binaryFile, service: "ssh-login" );
		log_message( data: build_detection_report( app: "Django", version: djangoVer[0], install: binaryFile, cpe: cpe ) );
	}
}
ssh_close_connection();

