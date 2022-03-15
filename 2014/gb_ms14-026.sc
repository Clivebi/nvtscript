if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804452" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-1806" );
	script_bugtraq_id( 67286 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-05-14 16:10:33 +0530 (Wed, 14 May 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft .NET Framework Privilege Elevation Vulnerability (2958732)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS14-026." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the framework not properly restricting access to certain
application objects related to TypeFilterLevel checks." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to bypass certain security
restrictions." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 1.1, 2.0, 3.5, 3.5.1, 4.0 and 4.5 and 4.5.1." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2958732" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2014/ms14-026" );
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
if(hotfix_check_sp( win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8_1: 1, win8_1x64: 1, win2012: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "system.runtime.remoting.dll" );
		if(dllVer){
			if(( hotfix_check_sp( win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1022" ) || version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2035" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34107" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36105" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34106" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36104" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34106" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36114" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5482" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7056" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6415" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7054" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8002" ) || version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8605" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4251" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7056" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3658" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7054" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "1.1.4322.2000", test_version2: "1.1.4322.2505" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

