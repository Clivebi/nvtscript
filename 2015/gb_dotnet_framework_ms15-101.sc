if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805978" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-2504", "CVE-2015-2526" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-09-09 09:48:35 +0530 (Wed, 09 Sep 2015)" );
	script_name( "Microsoft .NET Framework Privilege Elevation Vulnerabilities (3089662)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-101." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An unspecified error in the way that the .NET Framework validates the number
    of objects in memory before copying those objects into an array.

  - Application fails to properly handle certain specially crafted requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to conduct denial-of-service attack and take complete control of an affected
  system." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 2.0 Service Pack 2

  - Microsoft .NET Framework 3.5

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 4

  - Microsoft .NET Framework 4.5, 4.5.1, and 4.5.2

  - Microsoft .NET Framework 4.6 and 4.6 RC" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3089662" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms15-101" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "System.Drawing.dll" );
		if(dllVer){
			if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.4258" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.4258";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8662" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.5700 - 2.0.50727.8662";
				}
			}
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.6428" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.6428";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8662" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8000 - 2.0.50727.8662";
				}
			}
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.8016" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.8016";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8662" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8600 - 2.0.50727.8662";
				}
			}
			if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8662" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8600 - 2.0.50727.8662";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.5492" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.5492";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8662" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8600 - 2.0.50727.8662";
				}
			}
			if(hotfix_check_sp( winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.0", test_version2: "4.0.30319.1035" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.000 - 4.0.30319.1035";
				}
				if(version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2062" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.2000 - 4.0.30319.2062";
				}
			}
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34262" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34262";
				}
				if(version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36304" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36304";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34269" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34269";
				}
				if(version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36309" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36309";
				}
			}
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34261" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34261";
				}
				if(version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36304" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36304";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.90" )){
					VULN1 = TRUE;
					file_checked = path + "System.Drawing.dll";
				}
			}
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.92" )){
					VULN1 = TRUE;
					vulnerable_range = "4.6 - 4.6.92";
				}
			}
			if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.92" )){
					VULN1 = TRUE;
					vulnerable_range = "4.6 - 4.6.92";
				}
			}
		}
		dllVer2 = fetch_file_version( sysPath: path, file_name: "System.ComponentModel.DataAnnotations.dll" );
		if(dllVer2){
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34267" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34267";
				}
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36307" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36307";
				}
			}
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0){
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34261" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34261";
				}
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36310" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36310";
				}
			}
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34261" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34261";
				}
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36304" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36304";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer2, test_version: "4.6", test_version2: "4.6.102" )){
					VULN2 = TRUE;
					vulnerable_range = "4.6 - 4.6.102";
				}
			}
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer2, test_version: "4.6", test_version2: "4.6.92" )){
					VULN2 = TRUE;
					vulnerable_range = "4.6 - 4.6.92";
				}
			}
		}
	}
}
if(VULN1){
	report = "File checked:     " + path + "System.Drawing.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + vulnerable_range + "\n";
	security_message( data: report );
}
if(VULN2){
	report = "File checked:     " + path + "System.ComponentModel.DataAnnotations.dll" + "\n" + "File version:     " + dllVer2 + "\n" + "Vulnerable range: " + vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

