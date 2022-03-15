if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.817320" );
	script_version( "2021-08-11T08:56:08+0000" );
	script_cve_id( "CVE-2020-1476", "CVE-2020-1046" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-11 08:56:08 +0000 (Wed, 11 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 15:28:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2020-08-12 08:49:56 +0530 (Wed, 12 Aug 2020)" );
	script_name( "Microsoft .NET Framework Multiple Vulnerabilities (KB4570506)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4570506" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to

  - An error when ASP.NET or .NET web applications running on IIS improperly
    allow access to cached files.

  - An error when Microsoft .NET Framework processes input." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain access to restricted files and take control of an affected system" );
	script_tag( name: "affected", value: "Microsoft .NET Framework 3.5.1, 4.5.2, 4.6, 4.6.1, 4.6.2, 4.7, 4.7.1, 4.7.2, 4.8 for Microsoft Windows 7 SP1 and Microsoft Windows Server 2008 R2 SP1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4570506" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
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
					dllVer = fetch_file_version( sysPath: dotPath, file_name: "Webengine.dll" );
					if(dllVer){
						if( version_in_range( version: dllVer, test_version: "2.0.50727", test_version2: "2.0.50727.8950" ) ){
							vulnerable_range = "2.0.50727 - 2.0.50727.8950";
							break;
						}
						else {
							if( version_in_range( version: dllVer, test_version: "4.0", test_version2: "4.0.30319.36659" ) ){
								vulnerable_range = "4.0 - 4.0.30319.36659";
								break;
							}
							else {
								if( version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.7.3649" ) ){
									vulnerable_range = "4.6 - 4.7.3649";
									break;
								}
								else {
									if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.4209" )){
										vulnerable_range = "4.8 - 4.8.4209";
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
				dllVer = fetch_file_version( sysPath: dotPath, file_name: "Webengine.dll" );
				if(dllVer){
					if( version_in_range( version: dllVer, test_version: "2.0.50727", test_version2: "2.0.50727.8950" ) ){
						vulnerable_range = "2.0.50727 - 2.0.50727.8950";
						break;
					}
					else {
						if( version_in_range( version: dllVer, test_version: "4.0", test_version2: "4.0.30319.36659" ) ){
							vulnerable_range = "4.0 - 4.0.30319.36659";
							break;
						}
						else {
							if( version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.7.3649" ) ){
								vulnerable_range = "4.6 - 4.7.3649";
								break;
							}
							else {
								if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.4209" )){
									vulnerable_range = "4.8 - 4.8.4209";
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
			dllVer = fetch_file_version( sysPath: dotPath, file_name: "Webengine.dll" );
			if(dllVer){
				if( version_in_range( version: dllVer, test_version: "2.0.50727", test_version2: "2.0.50727.8950" ) ){
					vulnerable_range = "2.0.50727 - 2.0.50727.8950";
					break;
				}
				else {
					if( version_in_range( version: dllVer, test_version: "4.0", test_version2: "4.0.30319.36659" ) ){
						vulnerable_range = "4.0 - 4.0.30319.36659";
						break;
					}
					else {
						if( version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.7.3649" ) ){
							vulnerable_range = "4.6 - 4.7.3649";
							break;
						}
						else {
							if(version_in_range( version: dllVer, test_version: "4.8", test_version2: "4.8.4209" )){
								vulnerable_range = "4.8 - 4.8.4209";
								break;
							}
						}
					}
				}
			}
		}
	}
	if(vulnerable_range){
		report = report_fixed_ver( file_checked: dotPath + "Webengine.dll", file_version: dllVer, vulnerable_range: vulnerable_range );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

