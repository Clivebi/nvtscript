if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806614" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-6096", "CVE-2015-6099", "CVE-2015-6115" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-11-11 09:47:24 +0530 (Wed, 11 Nov 2015)" );
	script_name( "Microsoft .NET Framework Privilege Elevation Vulnerabilities (3104507)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-118." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the .NET Framework DTD parsing of certain specially crafted XML
  files.

  - ASP.NET improperly validates values in HTTP requests.

  - An error in the .NET Framework component which does not properly implement the
  Address Space Layout Randomization (ASLR) security feature." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to gain read access to local files, bypass the security feature and then load
  additional malicious code, inject client-side script into a users browser and
  ultimately modify or spoof content, conduct phishing activities, disclose
  information, or perform any action on the vulnerable website that the target
  user has permission to perform." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 2.0 Service Pack 2

  - Microsoft .NET Framework 3.5

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 4

  - Microsoft .NET Framework 4.5, 4.5.1, and 4.5.2

  - Microsoft .NET Framework 4.6, 4.6 RC" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3104507" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-118" );
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
	VULN1 = FALSE;
	VULN2 = FALSE;
	VULN3 = FALSE;
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "System.Deployment.dll" );
		if(dllVer){
			if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.4259" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.4259";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8670" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8000 - 2.0.50727.8670";
				}
			}
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.6429" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.6429";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8670" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8000 - 2.0.50727.8670";
				}
			}
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.8017" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.8017";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8670" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8600 - 2.0.50727.8670";
				}
			}
			if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8670" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8600 - 2.0.50727.8670";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.5493" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.5493";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8670" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8000 - 2.0.50727.8670";
				}
			}
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34273" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34273";
				}
				if(version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36322" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36322";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.117.0" )){
					VULN1 = TRUE;
					vulnerable_range = "4.6 - 4.6.117.0";
				}
			}
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.113" )){
					VULN1 = TRUE;
					vulnerable_range = "4.6 - 4.6.113";
				}
			}
			if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.113" )){
					VULN1 = TRUE;
					vulnerable_range = "4.6 - 4.6.113";
				}
			}
		}
		dllpath = path + "\\SetupCache";
		dllVer2 = fetch_file_version( sysPath: dllpath, file_name: "Setupengine.dll" );
		if(dllVer2){
			if(hotfix_check_sp( winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_is_less( version: dllVer2, test_version: "10.0.30319.1040" )){
					VULN2 = TRUE;
					vulnerable_range = "Less than 10.0.30319.1040";
				}
			}
			if(hotfix_check_sp( winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_in_range( version: dllVer2, test_version: "12.0", test_version2: "12.0.51720.34279" )){
					VULN2 = TRUE;
					vulnerable_range = "12.0 - 12.0.51720.34279";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer2, test_version: "14.0", test_version2: "14.0.117" )){
					VULN2 = TRUE;
					vulnerable_range = "14.0 - 14.0.117";
				}
			}
		}
		dllVer3 = fetch_file_version( sysPath: path, file_name: "System.web.dll" );
		if(dllVer3){
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer3, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34273" )){
					VULN3 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34273";
				}
				if(version_in_range( version: dllVer3, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36322" )){
					VULN3 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36322";
				}
			}
			if(hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer3, test_version: "4.6", test_version2: "4.6.113" )){
					VULN3 = TRUE;
					vulnerable_range = "4.6 - 4.6.113";
				}
			}
		}
	}
	if(VULN1){
		report = "File checked:     " + path + "\\System.Deployment.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + vulnerable_range + "\n";
		security_message( data: report );
	}
	if(VULN2){
		report = "File checked:     " + path + "\\SetupCache\\Setupengine.dll" + "\n" + "File version:     " + dllVer2 + "\n" + "Vulnerable range: " + vulnerable_range + "\n";
		security_message( data: report );
	}
	if(VULN3){
		report = "File checked:     " + path + "System.web.dll" + "\n" + "File version:     " + dllVer3 + "\n" + "Vulnerable range: " + vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

