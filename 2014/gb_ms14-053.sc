if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804480" );
	script_version( "2020-06-09T08:59:39+0000" );
	script_cve_id( "CVE-2014-4072" );
	script_bugtraq_id( 69603 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-06-09 08:59:39 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2014-09-10 09:34:51 +0530 (Wed, 10 Sep 2014)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Microsoft .NET Framework Denial of Service Vulnerability (2990931)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS14-053." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error within
  a hash generation function when hashing requests and can be exploited to
  cause a hash collision resulting in high CPU consumption via specially
  crafted requests." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to cause a denial of service." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 1.1, 2.0, 3.0, 3.5, 3.5.1, 4.0, 4.5, 4.5.1 and 4.5.2." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS14-053" );
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
		dllVer = fetch_file_version( sysPath: path, file_name: "mscorlib.dll" );
		if(dllVer){
			if(( hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "1.1.4322.2000", test_version2: "1.1.4322.2509" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
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
		}
	}
}
key2 = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\";
for item in registry_enum_keys( key: key2 ) {
	path = registry_get_sz( key: key2 + item, item: "All Assemblies In" );
	if(path){
		dllVer = fetch_file_version( sysPath: path, file_name: "system.identitymodel.dll" );
		if(dllVer){
			if(( hotfix_check_sp( win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "3.0.4506.4000", test_version2: "3.0.4506.4067" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "3.0.4506.8000", test_version2: "3.0.4506.8001" ) || version_in_range( version: dllVer, test_version: "3.0.4506.8600", test_version2: "3.0.4506.8634" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "3.0.4506.6400", test_version2: "3.0.4506.6414" ) || version_in_range( version: dllVer, test_version: "3.0.4506.8600", test_version2: "3.0.4506.8634" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "3.0.4506.5400", test_version2: "3.0.4506.5462" ) || version_in_range( version: dllVer, test_version: "3.0.4506.8000", test_version2: "3.0.4506.8634" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "3.0.4506.4200", test_version2: "3.0.4506.4221" ) || version_in_range( version: dllVer, test_version: "3.0.4506.8600", test_version2: "3.0.4506.8634" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34233" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win8x64: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34229" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36240" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.34000", test_version2: "4.0.30319.34229" ) || version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36240" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}

