if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811039" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_cve_id( "CVE-2017-0248" );
	script_bugtraq_id( 98117 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-05-11 13:37:20 +0530 (Thu, 11 May 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft .NET Framework Security Bypass Vulnerability (4019112)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft KB4019112" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists when Microsoft .NET Framework
  (and .NET Core) components do not completely validate certificates." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions and perform unauthorized
  actions." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 4.5.2

  - Microsoft .NET Framework 4.6/4.6.1

  - Microsoft .NET Framework 4.6.2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4019112" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008: 3, win2008x64: 3, win7: 2, win7x64: 2, win2008r2: 2 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	dotPath = registry_get_sz( key: key + item, item: "Path" );
	if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
		if(!dllVer){
			exit( 0 );
		}
		if( version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.36391" ) ){
			Vulnerable_range = "4.0.30319.30000 - 4.0.30319.36391";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.1098" )){
				Vulnerable_range = "4.6 - 4.6.1098";
				VULN = TRUE;
			}
		}
		if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
			if(version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8758" )){
				Vulnerable_range = "2.0.50727.5700 - 2.0.50727.8758";
				VULN = TRUE;
			}
			key1 = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Client\\";
			brkVer = registry_get_sz( key: key1, item: "Version" );
			if(( brkVer == "4.6.01590" || brkVer == "4.6.01586" ) && IsMatchRegexp( dllVer, "(^4\\.6)" )){
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.1646" )){
					Vulnerable_range = "4.6 - 4.6.1646";
					VULN = TRUE;
				}
			}
		}
		if(VULN){
			report = "File checked:     " + dotPath + "\\system.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}

