if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803319" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2013-03-04 09:45:42 +0530 (Mon, 04 Mar 2013)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "McAfee VirusScan Enterprise Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of McAfee VirusScan Enterprise.

  The script detects the version of McAfee VirusScan Enterprise." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
key = "SOFTWARE\\McAfee\\DesktopProtection";
if(!registry_key_exists( key: key )){
	key = "SOFTWARE\\Wow6432Node\\McAfee\\DesktopProtection";
	if(!registry_key_exists( key: key )){
		exit( 0 );
	}
}
appName = registry_get_sz( key: key, item: "Product" );
if(ContainsString( appName, "McAfee VirusScan Enterprise" )){
	appVer = registry_get_sz( key: key, item: "szProductVer" );
	if(appVer){
		appPath = registry_get_sz( key: key, item: "szInstallDir" );
		if(appPath){
			appPath += "Readme.txt";
			txtRead = smb_read_file( fullpath: appPath, offset: 0, count: 500000 );
			fileVer = eregmatch( pattern: "Version ([0-9.]+[a-z])", string: txtRead );
			verRegex = "^([0-9.]+)";
			if(fileVer[1]){
				appVer = fileVer[1];
				verRegex = "^([0-9.]+[a-z])";
			}
			set_kb_item( name: "McAfee/VirusScan/Win/Ver", value: appVer );
			register_and_report_cpe( app: appName, ver: appVer, concluded: appVer, base: "cpe:/a:mcafee:virusscan_enterprise:", expr: verRegex, insloc: appPath );
		}
	}
}

