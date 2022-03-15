if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108517" );
	script_version( "2019-07-31T09:47:07+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-31 09:47:07 +0000 (Wed, 31 Jul 2019)" );
	script_tag( name: "creation_date", value: "2018-12-12 10:15:08 +0100 (Wed, 12 Dec 2018)" );
	script_name( "SMB: Gather file version info for authenticated scans" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "This script gathers the version of various
  Microsoft Windows files and saves/caches them internally for faster access by
  other scripts during authenticated scans." );
	script_tag( name: "qod_type", value: "executable_version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
for file in make_list( "edgehtml.dll",
	 "mshtml.dll" ) {
	vers = fetch_file_version( sysPath: sysPath, file_name: file );
	if(vers && IsMatchRegexp( vers, "^[0-9]+\\." )){
		set_kb_item( name: "SMB/lsc_file_version_cache/available", value: TRUE );
		set_kb_item( name: "SMB/lsc_file_version_cache/" + file + "/available", value: TRUE );
		set_kb_item( name: "SMB/lsc_file_version_cache/" + file + "/infos", value: sysPath + "\\" + file + "#--#" + vers );
	}
}
exit( 0 );

