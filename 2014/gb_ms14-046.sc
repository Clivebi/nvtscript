if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804740" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-4062" );
	script_bugtraq_id( 69145 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-08-13 16:07:41 +0530 (Wed, 13 Aug 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft .NET Framework Security Bypass Vulnerability (2984625)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS14-046." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is triggered when handling specially crafted website content due to the
  Address Space Layout Randomization (ASLR) security feature." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute of arbitrary code
  and bypass certain security mechanism." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 2.0 Service Pack 2, 3.0 Service Pack 2, 3.5, 3.5.1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/security/bulletin/ms14-046" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2984625" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "mscorlib.dll" );
		if(dllVer){
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4251" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7066" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6418" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7056" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_is_less( version: dllVer, test_version: "2.0.50727.8007" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8611" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5482" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.8629" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
key2 = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\";
for item in registry_enum_keys( key: key2 ) {
	path = registry_get_sz( key: key2 + item, item: "All Assemblies In" );
	if(path){
		dllv2 = fetch_file_version( sysPath: path, file_name: "system.identitymodel.dll" );
		if(dllv2){
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllv2, test_version: "3.0.4506.4000", test_version2: "3.0.4506.4222" ) || version_in_range( version: dllv2, test_version: "3.0.4506.7000", test_version2: "3.0.4506.7096" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllv2, test_version: "3.0.4506.6000", test_version2: "3.0.4506.6415" ) || version_in_range( version: dllv2, test_version: "3.0.4506.7000", test_version2: "3.0.4506.7081" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_is_less( version: dllv2, test_version: "3.0.4506.8002" ) || version_in_range( version: dllv2, test_version: "3.0.4506.8600", test_version2: "3.0.4506.8601" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllv2, test_version: "3.0.4506.5000", test_version2: "3.0.4506.5460" ) || version_in_range( version: dllv2, test_version: "3.0.4506.7082", test_version2: "3.0.4506.7081" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

