if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805178" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2015-1672", "CVE-2015-1673" );
	script_bugtraq_id( 74482, 74487 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2015-05-13 09:21:10 +0530 (Wed, 13 May 2015)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft .NET Framework Privilege Elevation Vulnerability (3057134)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS15-048." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to improper handling of objects
  in memory by .NET's Windows Forms (WinForms) libraries and error when decrypting
  specially crafted XML data." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain elevated privileges or disrupt the availability of
  applications that use the .NET framework." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 1.1 Service Pack 1

  - Microsoft .NET Framework 2.0 Service Pack 2

  - Microsoft .NET Framework 3.5

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 4

  - Microsoft .NET Framework 4.5, 4.5.1, and 4.5.2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3057134" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-048" );
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
		dllVer = fetch_file_version( sysPath: path, file_name: "system.windows.forms.dll" );
		if(dllVer){
			if(( hotfix_check_sp( win2003: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "1.1.4322.2000", test_version2: "1.1.4322.2511" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3666" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8654" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4256" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8652" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6426" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8652" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8652" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8014" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5490" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8652" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win2003: 3, winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1031" ) || version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2056" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34250" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36286" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34249" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36285" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34249" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36285" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
		dllVer2 = fetch_file_version( sysPath: path, file_name: "System.Security.dll" );
		if(dllVer2){
			if(( hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3664" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4255" ) || version_in_range( version: dllVer2, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8651" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6425" ) || version_in_range( version: dllVer2, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8651" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8651" ) || version_in_range( version: dllVer2, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8014" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5489" ) || version_in_range( version: dllVer2, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8651" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win2003: 3, winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1030" ) || version_in_range( version: dllVer2, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2055" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34251" ) || version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36287" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34247" ) || version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36282" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1 ) > 0 ) && ( version_in_range( version: dllVer2, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34247" ) || version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36282" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

