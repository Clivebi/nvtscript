if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800108" );
	script_version( "2021-06-15T12:39:35+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-15 12:39:35 +0000 (Tue, 15 Jun 2021)" );
	script_tag( name: "creation_date", value: "2008-10-04 09:54:24 +0200 (Sat, 04 Oct 2008)" );
	script_name( "Adobe Reader Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "Detects the installed version of Adobe Reader." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("cpe.inc.sc");
require("host_details.inc.sc");
require("ssh_func.inc.sc");
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
adobePath = ssh_find_file( file_name: "/AcroVersion$", useregex: TRUE, sock: sock );
for path in adobePath {
	path = chomp( path );
	if(!path){
		continue;
	}
	adobeVer = ssh_get_bin_version( full_prog_name: "cat", version_argv: path, ver_pattern: "^[0-9.]{3,}(_SU[0-9])?$" );
	if(adobeVer){
		set_kb_item( name: "Adobe/Reader/Linux/Version", value: adobeVer[0] );
		set_kb_item( name: "Adobe/Air_or_Flash_or_Reader/Linux/Installed", value: TRUE );
		cpe = build_cpe( value: adobeVer[0], exp: "^([0-9.]{3,}(_SU[0-9])?)$", base: "cpe:/a:adobe:acrobat_reader:" );
		if(!cpe){
			cpe = "cpe:/a:adobe:acrobat_reader";
		}
		register_product( cpe: cpe, location: path, service: "ssh-login", port: 0 );
		log_message( data: build_detection_report( app: "Adobe Reader", version: adobeVer[0], install: path, cpe: cpe, concluded: adobeVer[0] ) );
	}
}
ssh_close_connection();

