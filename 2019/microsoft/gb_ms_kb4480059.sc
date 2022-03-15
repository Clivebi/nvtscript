if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814720" );
	script_version( "2021-09-06T13:01:39+0000" );
	script_cve_id( "CVE-2019-0545" );
	script_bugtraq_id( 106405 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-06 13:01:39 +0000 (Mon, 06 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-14 20:54:00 +0000 (Mon, 14 Jan 2019)" );
	script_tag( name: "creation_date", value: "2019-01-09 10:08:38 +0530 (Wed, 09 Jan 2019)" );
	script_name( "Microsoft .NET Framework Information Disclosure Vulnerability (KB4480059)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4480059" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an error which allows
  to bypass CORS configuration." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  who successfully exploited the vulnerability to retrieve content, that is normally
  restricted, from a web application." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 4.5.2 on Microsoft Windows 7 for 32-bit/x64 Systems Service Pack 1

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 R2 for x64-based Systems Service Pack 1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4480059" );
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
if(hotfix_check_sp( win7: 2, win7x64: 2, win2008: 3, win2008x64: 3, win2008r2: 2 ) <= 0){
	exit( 0 );
}
if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\.NETFramework" )){
	if(!registry_key_exists( key: "SOFTWARE\\Microsoft\\ASP.NET" )){
		exit( 0 );
	}
}
key_list = make_list( "SOFTWARE\\Microsoft\\.NETFramework\\",
	 "SOFTWARE\\Microsoft\\ASP.NET\\" );
for key in key_list {
	if(ContainsString( key, ".NETFramework" )){
		for item in registry_enum_keys( key: key ) {
			NetPath = registry_get_sz( key: key + item, item: "InstallRoot" );
			if(NetPath && ContainsString( NetPath, "\\Microsoft.NET\\Framework" )){
				for item in registry_enum_keys( key: key ) {
					dotPath = NetPath + item;
					dllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
					if(dllVer){
						if(version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36489" )){
							VULN = TRUE;
							break;
						}
					}
				}
			}
		}
	}
	if(( !VULN ) && ContainsString( key, "ASP.NET" )){
		for item in registry_enum_keys( key: key ) {
			dotPath = registry_get_sz( key: key + item, item: "Path" );
			if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
				dllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
				if(dllVer){
					if(version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36489" )){
						VULN = TRUE;
						break;
					}
				}
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( file_checked: dotPath + "system.dll", file_version: dllVer, vulnerable_range: "4.0.30319.30000 - 4.0.30319.36489" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

