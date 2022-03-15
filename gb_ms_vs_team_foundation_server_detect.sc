if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802961" );
	script_version( "2020-12-10T13:32:24+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-12-10 13:32:24 +0000 (Thu, 10 Dec 2020)" );
	script_tag( name: "creation_date", value: "2012-09-12 11:27:31 +0530 (Wed, 12 Sep 2012)" );
	script_name( "Microsoft Visual Studio Team Foundation / Azure DevOps Server Detection (Windows SMB Login)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "summary", value: "SMB login based detection of Microsoft Visual Studio Team Foundation /
  Azure DevOps Server." );
	script_tag( name: "qod_type", value: "registry" );
	exit( 0 );
}
require("cpe.inc.sc");
require("smb_nt.inc.sc");
require("host_details.inc.sc");
require("secpod_smb_func.inc.sc");
mstfkey = "SOFTWARE\\Microsoft\\TeamFoundationServer\\";
if(!registry_key_exists( key: mstfkey )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	tfName = registry_get_sz( key: key + item, item: "DisplayName" );
	if(ContainsString( tfName, "Microsoft Team Foundation Server" )){
		tfNum = eregmatch( pattern: "[0-9.]+ (Update [0-9.]+)?", string: tfName );
		tfVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(tfVer){
			insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insPath){
				if( IsMatchRegexp( tfVer, "^12\\." ) ){
					insPath = registry_get_sz( key: mstfkey + "12.0", item: "InstallPath" );
				}
				else {
					if( IsMatchRegexp( tfVer, "^14\\." ) ){
						insPath = registry_get_sz( key: mstfkey + "14.0", item: "InstallPath" );
					}
					else {
						if( IsMatchRegexp( tfVer, "^15\\." ) ){
							insPath = registry_get_sz( key: mstfkey + "15.0", item: "InstallPath" );
						}
						else {
							if(IsMatchRegexp( tfVer, "^16\\." )){
								insPath = registry_get_sz( key: mstfkey + "16.0", item: "InstallPath" );
							}
						}
					}
				}
				if(!insPath){
					insPath = "Could not find the install location from registry";
				}
			}
			set_kb_item( name: "MS/VS/Team/Foundation/Server/Ver", value: tfVer );
			set_kb_item( name: "MS/VS/Team/Foundation/Server/Path", value: insPath );
			if( tfNum[0] ){
				cpe = build_cpe( value: tfVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:visual_studio_team_foundation_server:" + tfNum[0] );
			}
			else {
				cpe = build_cpe( value: tfVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:visual_studio_team_foundation_server:" + tfVer );
			}
			if(!cpe){
				cpe = "cpe:/a:microsoft:visual_studio_team_foundation_server";
			}
			register_product( cpe: cpe, location: insPath, port: 0, service: "smb-login" );
			log_message( data: build_detection_report( app: "Microsoft Visual Studio Team Foundation Server", version: tfVer, install: insPath, cpe: cpe, concluded: tfVer ) );
		}
	}
	if(ContainsString( tfName, "AzureDevOpsCore2019" ) || ContainsString( tfName, "AzureDevOpsCore2020" )){
		tfVer = registry_get_sz( key: key + item, item: "DisplayVersion" );
		if(tfVer){
			insPath = registry_get_sz( key: key + item, item: "InstallLocation" );
			if(!insPath){
				if( IsMatchRegexp( tfVer, "^17\\." ) ){
					insPath = registry_get_sz( key: mstfkey + "17.0", item: "InstallPath" );
					if(!insPath){
						insPath = "Could not find the install location from registry";
					}
				}
				else {
					if(IsMatchRegexp( tfVer, "^18\\." )){
						insPath = registry_get_sz( key: mstfkey + "18.0", item: "InstallPath" );
						if(!insPath){
							insPath = "Could not find the install location from registry";
						}
					}
				}
			}
			set_kb_item( name: "MS/Azure/DevOps/Server/Ver", value: tfVer );
			set_kb_item( name: "MS/Azure/DevOps/Server/Path", value: insPath );
			cpe = build_cpe( value: tfVer, exp: "^([0-9.]+)", base: "cpe:/a:microsoft:azure_devops_server:" + tfVer );
			if(!cpe){
				cpe = "cpe:/a:microsoft:azure_devops_server";
			}
			register_product( cpe: cpe, location: insPath, port: 0, service: "smb-login" );
			log_message( data: build_detection_report( app: "Microsoft Azure DevOps Server", version: tfVer, install: insPath, cpe: cpe, concluded: tfVer ) );
			exit( 0 );
		}
	}
}
exit( 0 );

