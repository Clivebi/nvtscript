if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900979" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-23 07:01:19 +0100 (Mon, 23 Nov 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Labtam ProFTP Version Detection" );
	script_tag( name: "summary", value: "This script detects the installed version of Labtam ProFTP.

The script logs in via smb, searches for ProFTP in the registry
and gets the version from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Lab-NC\\ProFTP",
		 "SOFTWARE\\Labtam\\ProFtp" );
	key_list2 = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ProFTP" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Lab-NC\\ProFTP",
			 "SOFTWARE\\Wow6432Node\\Labtam\\ProFtp" );
		key_list2 = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\App Paths\\ProFTP" );
	}
}
if(!registry_key_exists( key: "SOFTWARE\\Lab-NC\\ProFTP" )){
	if(!registry_key_exists( key: "SOFTWARE\\Labtam\\ProFtp" )){
		if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Lab-NC\\ProFTP" )){
			if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Labtam\\ProFtp" )){
				exit( 0 );
			}
		}
	}
}
if(isnull( key_list && key_list2 )){
	exit( 0 );
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		if(IsMatchRegexp( item, "[0-9]\\.[0-9]" )){
			ftpVer = item;
			for key1 in key_list2 {
				ftpPath = registry_get_sz( key: key1, item: "Path" );
				if(!ftpPath){
					ftpPath = "Couldn find the install location from registry";
				}
			}
			if(ftpVer){
				set_kb_item( name: "Labtam/ProFTP/Ver", value: ftpVer );
				cpe = build_cpe( value: item, exp: "^([0-9.]+)", base: "cpe:/a:labtam-inc:proftp:" );
				if(isnull( cpe )){
					cpe = "cpe:/a:labtam-inc:proftp:";
				}
				register_product( cpe: cpe, location: ftpPath );
				log_message( data: build_detection_report( app: "Labtam ProFTP", version: ftpVer, install: ftpPath, cpe: cpe, concluded: ftpVer ) );
			}
		}
	}
}

