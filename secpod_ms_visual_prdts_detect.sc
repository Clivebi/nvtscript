if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900808" );
	script_version( "2021-09-01T14:04:04+0000" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-01 14:04:04 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-03 06:30:10 +0200 (Mon, 03 Aug 2009)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Microsoft Visual Products Version Detection" );
	script_tag( name: "summary", value: "Detects the installed version of Microsoft Visual Products.

  This script finds the installed product version of Microsoft Visual
  Product(s)." );
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
checkduplicate = "";
NET_LIST = make_list( "^(7\\..*)",
	 "cpe:/a:microsoft:visual_studio_.net:2003:",
	 "^(8\\..*)",
	 "cpe:/a:microsoft:visual_studio_.net:2005:",
	 "^(9\\..*)",
	 "cpe:/a:microsoft:visual_studio_.net:2008:" );
NET_MAX = max_index( NET_LIST );
STUDIO_LIST = make_list( "^(7\\..*)",
	 "cpe:/a:microsoft:visual_studio:2003:",
	 "Microsoft VisualStudio 2003",
	 "^(8\\..*)",
	 "cpe:/a:microsoft:visual_studio:2005:",
	 "Microsoft VisualStudio 2005",
	 "^(9\\..*)",
	 "cpe:/a:microsoft:visual_studio:2008:",
	 "Microsoft VisualStudio 2008",
	 "^(10\\..*)",
	 "cpe:/a:microsoft:visual_studio:2010:",
	 "Microsoft VisualStudio 2010",
	 "^(11\\..*)",
	 "cpe:/a:microsoft:visual_studio:2012:",
	 "Microsoft VisualStudio 2012",
	 "^(12\\..*)",
	 "cpe:/a:microsoft:visual_studio:2013:",
	 "Microsoft VisualStudio 2013",
	 "^(14\\..*)",
	 "cpe:/a:microsoft:visual_studio:2015",
	 "Microsoft VisualStudio 2015",
	 "^(15\\..*)",
	 "cpe:/a:microsoft:visual_studio:2017",
	 "Microsoft VisualStudio 2017",
	 "^(16\\..*)",
	 "cpe:/a:microsoft:visual_studio:2019",
	 "Microsoft VisualStudio 2019" );
STUDIO_MAX = max_index( STUDIO_LIST );
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\VisualStudio" )){
	if(!registry_key_exists( key: "SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio" )){
		exit( 0 );
	}
}
os_arch = get_kb_item( "SMB/Windows/Arch" );
if(!os_arch){
	exit( 0 );
}
if( ContainsString( os_arch, "x86" ) ){
	key_list = make_list( "SOFTWARE\\Microsoft\\VisualStudio\\" );
	visual_key_list = make_list( "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
}
else {
	if(ContainsString( os_arch, "x64" )){
		key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\VisualStudio\\",
			 "SOFTWARE\\Microsoft\\VisualStudio\\" );
		visual_key_list = make_list( "SOFTWARE\\Wow6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\",
			 "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\" );
	}
}
for visual_key in visual_key_list {
	for item in registry_enum_keys( key: visual_key ) {
		visualName = registry_get_sz( key: visual_key + item, item: "DisplayName" );
		if(( IsMatchRegexp( visualName, "Microsoft Visual Studio [0-9]+" ) && !ContainsString( visualName, "Tools" ) && !IsMatchRegexp( visualName, "KB[0-9]+" ) && !ContainsString( visualName, "Assemblies" ) && !ContainsString( visualName, "Explorer" ) && !ContainsString( visualName, "Diagnostics" ) && !ContainsString( visualName, "Language Pack" ) && !ContainsString( visualName, "Helper" ) && !ContainsString( visualName, "Devenv" ) && !ContainsString( visualName, "Prerequisites" ) && !ContainsString( visualName, "Shell" ) && !ContainsString( visualName, "Application" ) && !ContainsString( visualName, "Web Pages" ) && !ContainsString( visualName, "SDK" ) && !ContainsString( visualName, "Update" ) && !ContainsString( visualName, "Preparation" ) && !ContainsString( visualName, "XAML" ) ) || ( IsMatchRegexp( visualName, "Visual Studio (Community|Professional|Enterprise) [0-9]+" ) )){
			STUDIODETECT = TRUE;
			studioVer = registry_get_sz( key: visual_key + item, item: "DisplayVersion" );
			insPath = registry_get_sz( key: visual_key + item, item: "InstallLocation" );
			if(!insPath){
				insPath = "Could not find the install Location from registry";
			}
			if(studioVer){
				if(ContainsString( checkduplicate, studioVer + ", " )){
					continue;
				}
				checkduplicate += studioVer + ", ";
				set_kb_item( name: "Microsoft/VisualStudio_or_VisualStudio.NET/Installed", value: TRUE );
				set_kb_item( name: "Microsoft/VisualStudio/Ver", value: studioVer );
				STUDIOVER = TRUE;
				for(i = 0;i < STUDIO_MAX - 1;i = i + 3){
					cpe = build_cpe( value: studioVer, exp: STUDIO_LIST[i], base: STUDIO_LIST[i + 1] );
					if(cpe){
						cpe_final = cpe;
						app = visualName;
						register_and_report_cpe( app: app, ver: studioVer, concluded: app + " version " + studioVer, cpename: cpe_final, insloc: insPath );
					}
				}
			}
		}
	}
	if(IsMatchRegexp( visualName, "Visual Studio \\.NET [A-Za-z0-9]+" )){
		netVer = registry_get_sz( key: visual_key + item, item: "DisplayVersion" );
		if(netVer != NULL){
			set_kb_item( name: "Microsoft/VisualStudio_or_VisualStudio.Net/Installed", value: TRUE );
			set_kb_item( name: "Microsoft/VisualStudio.Net/Ver", value: netVer );
			insPath = registry_get_sz( key: visual_key + item, item: "InstallLocation" );
			if(!insPath){
				insPath = "Could not find the install Location from registry";
			}
			for(i = 0;i < NET_MAX - 1;i = i + 2){
				cpe = build_cpe( value: netVer, exp: NET_LIST[i], base: NET_LIST[i + 1] );
				if(cpe){
					cpe_final = cpe;
					app = visualName;
					register_and_report_cpe( app: app, ver: netVer, concluded: app + " version " + netVer, cpename: cpe_final, insloc: insPath );
				}
			}
		}
	}
}
if(STUDIODETECT && !STUDIOVER){
	for key in key_list {
		for item in registry_enum_keys( key: key ) {
			visualName = registry_get_sz( key: key + item, item: "ApplicationID" );
			if(ContainsString( visualName, "VisualStudio" )){
				insPath = registry_get_sz( key: key + item, item: "InstallDir" );
				if( !insPath ){
					continue;
				}
				else {
					devenv = fetch_file_version( sysPath: insPath, file_name: "devenv.exe" );
					if( !devenv ){
						continue;
					}
					else {
						set_kb_item( name: "Microsoft/VisualStudio_or_VisualStudio.NET/Installed", value: TRUE );
						set_kb_item( name: "Microsoft/VisualStudio/Ver", value: devenv );
						for(i = 0;i < STUDIO_MAX - 1;i = i + 3){
							cpe = build_cpe( value: devenv, exp: STUDIO_LIST[i], base: STUDIO_LIST[i + 1] );
							if(cpe){
								cpe_final = cpe;
								app = STUDIO_LIST[i + 2];
								register_and_report_cpe( app: app, ver: devenv, concluded: app + " version " + devenv, cpename: cpe_final, insloc: insPath );
							}
						}
					}
				}
			}
		}
	}
}

