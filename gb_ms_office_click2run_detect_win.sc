if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812996" );
	script_version( "$Revision: 10905 $" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-08-10 16:32:11 +0200 (Fri, 10 Aug 2018) $" );
	script_tag( name: "creation_date", value: "2018-03-23 08:52:52 +0530 (Fri, 23 Mar 2018)" );
	script_name( "Microsoft Office ClicktoRun Version Detection (Windows)" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft
  Office ClicktoRun on Windows.

  The script logs in via smb, searches for 'Office ClicktoRun' in the registry
  and gets the version from registry." );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Product detection" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion", "SMB/Windows/Arch" );
	script_require_ports( 139, 445 );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("cpe.inc.sc");
require("host_details.inc.sc");
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\Office\\ClickToRun" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Microsoft\\Office\\ClickToRun" )){
		exit( 0 );
	}
}
TMP_OFFICE_LIST = make_list( "^(14\\..*)",
	 "cpe:/a:microsoft:office:2010:c2r:",
	 "Microsoft Office Click-to-Run 2010",
	 "^(15\\..*)",
	 "cpe:/a:microsoft:office:2013:c2r:",
	 "Microsoft Office Click-to-Run 2013",
	 "^(16\\..*)",
	 "cpe:/a:microsoft:office:2016:c2r:",
	 "Microsoft Office Click-to-Run 2016" );
MAX = max_index( TMP_OFFICE_LIST );
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Microsoft\\Office\\ClickToRun\\Configuration",
			 "SOFTWARE\\Wow6432Node\\Microsoft\\Office\\ClickToRun\\Configuration" );
	}
}
for key in key_list {
	MSOffVer = registry_get_sz( key: key, item: "VersionToReport" );
	if(MSOffVer){
		MSOffPath = registry_get_sz( key: key, item: "InstallationPath" );
		if(!MSOffPath){
			MSOffPath = "Unable to locate installation path from registry";
		}
		UpChannel = registry_get_sz( key: key, item: "UpdateChannel" );
		if(!UpChannel){
			UpChannel = registry_get_sz( key: key, item: "CDNBaseUrl" );
		}
		if(UpChannel){
			if( ContainsString( UpChannel, "492350f6-3a01-4f97-b9c0-c7c6ddf67d60" ) ){
				UpdateChannel = "Monthly Channel";
			}
			else {
				if( ContainsString( UpChannel, "7ffbc6bf-bc32-4f92-8982-f9dd17fd3114" ) ){
					UpdateChannel = "Semi-Annual Channel";
					if(IsMatchRegexp( MSOffVer, "(8201|7766|7369|6965|6741|6001)\\." )){
						UpdateChannel = "Deferred Channel";
					}
				}
				else {
					if( ContainsString( UpChannel, "64256afe-f5d9-4f86-8936-8840a6a4f5be" ) ){
						UpdateChannel = "Monthly Channel (Targeted)";
					}
					else {
						if(ContainsString( UpChannel, "b8f9b850-328d-4355-9145-c59439a0c4cf" )){
							UpdateChannel = "Semi-Annual Channel (Targeted)";
						}
					}
				}
			}
			if(UpdateChannel){
				set_kb_item( name: "MS/Office/C2R/UpdateChannel", value: UpdateChannel );
			}
		}
		set_kb_item( name: "MS/Off/C2R/InstallPath", value: MSOffPath );
		set_kb_item( name: "MS/Off/C2R/Ver", value: MSOffVer );
		for(i = 0;i < MAX - 1;i = i + 3){
			cpe = build_cpe( value: MSOffVer, exp: TMP_OFFICE_LIST[i], base: TMP_OFFICE_LIST[i + 1] );
			if(!isnull( cpe )){
				cpe_final = cpe;
			}
			app = TMP_OFFICE_LIST[i + 2];
		}
		Platform = registry_get_sz( key: key, item: "Platform" );
		if(Platform && !ContainsString( Platform, "x86" ) && ContainsString( os_arch, "x64" )){
			set_kb_item( name: "MS/Off/C2R64/Ver", value: MSOffVer );
			for(i = 0;i < MAX - 1;i = i + 3){
				cpe = build_cpe( value: MSOffVer, exp: TMP_OFFICE_LIST[i], base: TMP_OFFICE_LIST[i + 1] + "x64:" );
				if(!isnull( cpe )){
					cpe_final = cpe;
				}
			}
		}
		register_and_report_cpe( app: app, ver: MSOffVer, concluded: "Microsoft Office Click-to-Run with Update Channel '" + UpdateChannel + "' and version:" + MSOffVer, cpename: cpe_final, insloc: MSOffPath );
		exit( 0 );
	}
}
exit( 0 );

