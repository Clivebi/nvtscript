if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814298" );
	script_version( "2021-06-22T11:00:29+0000" );
	script_cve_id( "CVE-2018-8517", "CVE-2018-8540" );
	script_bugtraq_id( 106075, 106073 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-28 12:58:00 +0000 (Mon, 28 Sep 2020)" );
	script_tag( name: "creation_date", value: "2018-12-12 08:32:46 +0530 (Wed, 12 Dec 2018)" );
	script_name( "Microsoft .NET Framework 4.5.2 Multiple Vulnerabilities (KB4470622)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4470622" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error when .NET Framework improperly handles special web requests.

  - An error when the Microsoft .NET Framework fails to validate input properly." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to cause a denial of service condition and take control of an affected system." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 4.5.2 for

  - Microsoft Windows 8.1 for 32-bit/x64

  - Microsoft Windows Server 2012 R2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4470622" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_require_ports( 139, 445 );
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
					sysdllVer = fetch_file_version( sysPath: dotPath, file_name: "workflowservicehostperformancecounters.dll" );
					if(sysdllVer){
						if(version_in_range( version: sysdllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36464" )){
							VULN = TRUE;
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
				sysdllVer = fetch_file_version( sysPath: dotPath, file_name: "workflowservicehostperformancecounters.dll" );
				if(sysdllVer){
					if(version_in_range( version: sysdllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36464" )){
						VULN = TRUE;
					}
				}
			}
		}
	}
	if(VULN){
		report = report_fixed_ver( file_checked: dotPath + "workflowservicehostperformancecounters.dll", file_version: sysdllVer, vulnerable_range: "4.0.30319.30000 - 4.0.30319.36464" );
		security_message( data: report );
		exit( 0 );
	}
}
exit( 99 );

