if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800553" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_version( "2020-03-27T14:05:33+0000" );
	script_tag( name: "last_modification", value: "2020-03-27 14:05:33 +0000 (Fri, 27 Mar 2020)" );
	script_tag( name: "creation_date", value: "2009-04-23 08:16:04 +0200 (Thu, 23 Apr 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_name( "ClamAV Version Detection (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "login/SSH/success" );
	script_exclude_keys( "ssh/no_linux_shell" );
	script_tag( name: "summary", value: "This script retrieves ClamAV Version." );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
SCRIPT_DESC = "ClamAV Version Detection (Linux)";
sock = ssh_login_or_reuse_connection();
if(!sock){
	exit( 0 );
}
getPath = ssh_find_bin( prog_name: "clamscan", sock: sock );
for binaryFile in getPath {
	binaryFile = chomp( binaryFile );
	if(!binaryFile){
		continue;
	}
	avVer = ssh_get_bin_version( full_prog_name: binaryFile, version_argv: "-V", ver_pattern: "ClamAV ([0-9.]+)", sock: sock );
	if(avVer[1] != NULL){
		set_kb_item( name: "ClamAV/installed", value: TRUE );
		set_kb_item( name: "ClamAV/Lin/Ver", value: avVer[1] );
		log_message( data: "Clam Anti Virus version " + avVer[1] + " running at" + " location " + binaryFile + " was detected on the host" );
		ssh_close_connection();
		cpe = build_cpe( value: avVer[1], exp: "^([0-9.]+)", base: "cpe:/a:clamav:clamav:" );
		if(!isnull( cpe )){
			register_host_detail( name: "App", value: cpe, desc: SCRIPT_DESC );
		}
		exit( 0 );
	}
}
ssh_close_connection();

