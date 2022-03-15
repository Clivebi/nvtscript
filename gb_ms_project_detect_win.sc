if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814337" );
	script_version( "2019-12-05T15:10:00+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-05 15:10:00 +0000 (Thu, 05 Dec 2019)" );
	script_tag( name: "creation_date", value: "2018-11-19 17:15:31 +0530 (Mon, 19 Nov 2018)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Project Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Project
  on Windows.

  The script logs in via smb, searches for Microsoft Project and gets the version
  from registry." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_smb_func.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
osArch = get_kb_item( "SMB/Windows/Arch" );
if(!osArch){
	exit( 0 );
}
if( ContainsString( osArch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( osArch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for key in key_list {
	for item in registry_enum_keys( key: key ) {
		appName = registry_get_sz( key: key + item, item: "DisplayName" );
		if(ContainsString( appName, "Microsoft Project" )){
			proVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
			if(!proVer){
				exit( 0 );
			}
			proPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!proPath){
				proPath = "Did not find install path from registry.";
			}
			set_kb_item( name: "Microsoft/Project/Win/Ver", value: proVer );
			cpe = build_cpe( value: proVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:project:" );
			if(isnull( cpe )){
				cpe = "cpe:/a:microsoft:project";
			}
			register_product( cpe: cpe, location: proPath, service: "smb-login", port: 0 );
			report = build_detection_report( app: appName, version: proVer, install: proPath, cpe: cpe, concluded: proVer );
			if(report){
				log_message( port: 0, data: report );
			}
		}
	}
}

