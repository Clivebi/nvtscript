if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900466" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-05-06 08:04:28 +0200 (Wed, 06 May 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Xpdf Version Detection" );
	script_tag( name: "vuldetect", value: "The script logs in via ssh, searches for executable 'xpdf' and
  queries the found executables via command line option '-v'." );
	script_tag( name: "summary", value: "The PDF viewer Xpdf is installed and its version is detected." );
	script_tag( name: "affected", value: "Xpdf on Linux." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
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
xpdfPaths = ssh_find_file( file_name: "/xpdf$", useregex: TRUE, sock: sock );
for executableFile in xpdfPaths {
	executableFile = chomp( executableFile );
	if(!executableFile){
		continue;
	}
	xpdfVer = ssh_get_bin_version( full_prog_name: executableFile, sock: sock, version_argv: "-v", ver_pattern: "xpdf version ([0-9]\\.[0-9]+([a-z]?))" );
	if(xpdfVer[1] != NULL){
		set_kb_item( name: "Xpdf/Linux/Ver", value: xpdfVer[1] );
		cpe = build_cpe( value: xpdfVer[1], exp: "^([0-9.]+([a-z0-9]+)?)", base: "cpe:/a:foolabs:xpdf:" );
		if(!isnull( cpe )){
			register_product( cpe: cpe, location: executableFile );
		}
		log_message( data: "Detected Xpdf version: " + xpdfVer[1] + "\nLocation: " + executableFile + "\nCPE: " + cpe + "\n\nConcluded from version identification result:\n" + xpdfVer[max_index( xpdfVer ) - 1] );
	}
}
ssh_close_connection();

