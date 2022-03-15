if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815107" );
	script_version( "2021-09-06T14:01:33+0000" );
	script_cve_id( "CVE-2019-0864", "CVE-2019-0820", "CVE-2019-0980", "CVE-2019-0981" );
	script_bugtraq_id( 108241, 108245, 108232, 108207 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-06 14:01:33 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-05-15 09:59:50 +0530 (Wed, 15 May 2019)" );
	script_name( "Microsoft .NET Framework Multiple DoS Vulnerabilities (KB4499408)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4499408" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple errors when .NET Framework or .NET Core improperly handle web requests.

  - An error when .NET Framework improperly handles objects in heap memory.

  - An error when .NET Framework and .NET Core improperly process RegEx strings." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to cause a denial of service condition." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 3.5, 4.5.2, 4.6, 4.6.1, 4.6.2, 4.7, 4.7.1, 4.7.2, 4.8 on Microsoft Windows 8.1 and Microsoft Windows Server 2012 R2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4499408" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4495608" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4495592" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4495585" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4495624" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) <= 0){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\.NETFramework" )){
	if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\ASP.NET" )){
		if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\" )){
			exit( 0 );
		}
	}
}
key_list = make_list( "SOFTWARE\\Microsoft\\.NETFramework\\",
	 "SOFTWARE\\Microsoft\\ASP.NET\\",
	 "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Full\\" );
for key in key_list {
	if(ContainsString( key, ".NETFramework" )){
		for item in registry_enum_keys( key: key ) {
			NetPath = registry_get_sz( key: key + item, item: "InstallRoot" );
			if(NetPath && ContainsString( NetPath, "\\Microsoft.NET\\Framework" )){
				for item in registry_enum_keys( key: key ) {
					dotPath = NetPath + item;
					dllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
					if(dllVer){
						if( version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8805" ) ){
							vulnerable_range = "2.0.50727.5700 - 2.0.50727.8805";
							break;
						}
						else {
							if( version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36542" ) ){
								vulnerable_range = "4.0.30319.30000 - 4.0.30319.36542";
								break;
							}
							else {
								if( version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.7.3415" ) ){
									vulnerable_range = "4.6 - 4.7.3415";
									break;
								}
								else {
									if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.3800" )){
										vulnerable_range = "4.8 - 4.8.3800";
										break;
									}
								}
							}
						}
					}
				}
			}
		}
	}
	if(( !vulnerable_range ) && ContainsString( key, "ASP.NET" )){
		for item in registry_enum_keys( key: key ) {
			dotPath = registry_get_sz( key: key + item, item: "Path" );
			if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
				dllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
				if(dllVer){
					if( version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8805" ) ){
						vulnerable_range = "2.0.50727.5700 - 2.0.50727.8805";
						break;
					}
					else {
						if( version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36542" ) ){
							vulnerable_range = "4.0.30319.30000 - 4.0.30319.36542";
							break;
						}
						else {
							if( version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.7.3415" ) ){
								vulnerable_range = "4.6 - 4.7.3415";
								break;
							}
							else {
								if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.3800" )){
									vulnerable_range = "4.8 - 4.8.3800";
									break;
								}
							}
						}
					}
				}
			}
		}
	}
	if(( !vulnerable_range ) && ContainsString( key, "NET Framework Setup" )){
		dotPath = registry_get_sz( key: key, item: "InstallPath" );
		if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
			dllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
			if(dllVer){
				if( version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36542" ) ){
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.36542";
				}
				else {
					if( version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.7.3415" ) ){
						vulnerable_range = "4.6 - 4.7.3415";
					}
					else {
						if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.3800" )){
							vulnerable_range = "4.8 - 4.8.3800";
						}
					}
				}
			}
		}
	}
	if(vulnerable_range){
		report = report_fixed_ver( file_checked: dotPath + "\\System.dll", file_version: dllVer, vulnerable_range: vulnerable_range );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

