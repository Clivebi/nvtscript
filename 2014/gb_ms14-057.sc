if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804777" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-4073", "CVE-2014-4121", "CVE-2014-4122" );
	script_bugtraq_id( 70313, 70351, 70312 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-10-15 11:15:20 +0530 (Wed, 15 Oct 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft .NET Framework Remote Code Execution Vulnerability (3000414)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS14-057." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An unspecified error related to .NET ClickOnce.

  - An unspecified error when handling internationalized resource identifiers.

  - An unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to bypass certain security restrictions and compromise a
  vulnerable system." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 2.0, 3.5, 3.5.1, 4.0, 4.5, 4.5.1 and 4.5.2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/3000414" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms14-057" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "System.dll" );
		if(dllVer){
			if(( hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3661" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8636" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4252" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7070" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6420" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7070" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8008" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8614" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5484" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7070" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win2003: 3, winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1025" ) || version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2044" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34237" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36249" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34238" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36250" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
		dllVer2 = fetch_file_version( sysPath: path, file_name: "System.Deployment.dll" );
		if(dllVer2){
			if(( hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3662" ) || version_in_range( version: dllVer2, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8640" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4254" ) || version_in_range( version: dllVer2, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8640" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6423" ) || version_in_range( version: dllVer2, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8640" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8011" ) || version_in_range( version: dllVer2, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8640" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5487" ) || version_in_range( version: dllVer2, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8640" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win2003: 3, winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1028" ) || version_in_range( version: dllVer2, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2047" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34243" ) || version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36255" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34242" ) || version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36254" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
		dllVer3 = fetch_file_version( sysPath: path, file_name: "mscorie.dll" );
		if(dllVer3){
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer3, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4251" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer3, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6418" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_in_range( version: dllVer3, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8007" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer3, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5482" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

