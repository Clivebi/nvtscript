if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805082" );
	script_version( "2020-06-09T05:48:43+0000" );
	script_cve_id( "CVE-2015-2460", "CVE-2015-2462", "CVE-2015-2455", "CVE-2015-2456", "CVE-2015-2463", "CVE-2015-2464" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-06-09 05:48:43 +0000 (Tue, 09 Jun 2020)" );
	script_tag( name: "creation_date", value: "2015-08-12 11:47:28 +0530 (Wed, 12 Aug 2015)" );
	script_name( "Microsoft .NET Framework Remote Code Execution Vulnerabilities (3078662)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS15-080." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to improper handling of
  TrueType fonts and OpenType fonts." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to gain access to potentially sensitive information and to execute
  arbitrary code on the affected system." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 3.0 Service Pack 2

  - Microsoft .NET Framework 3.5

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 4

  - Microsoft .NET Framework 4.5, 4.5.1, and 4.5.2

  - Microsoft .NET Framework 4.6 and 4.6 RC" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3078662" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS15-080" );
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
key = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\v3.0";
if(registry_key_exists( key: key )){
	path = registry_get_sz( key: key, item: "All Assemblies In" );
	if(path){
		dllVer = fetch_file_version( sysPath: path, file_name: "System.printing.dll" );
	}
	if(dllVer){
		if(hotfix_check_sp( win8: 1, win2012: 1 ) > 0){
			if(version_in_range( version: dllVer, test_version: "3.0.6920.6400", test_version2: "3.0.6920.6420" ) || version_in_range( version: dllVer, test_version: "3.0.6920.8600", test_version2: "3.0.6920.8683" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
		if(( hotfix_check_sp( win10: 1, win10x64: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "3.0.6920.8600", test_version2: "3.0.6920.8683" ) )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
		if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "3.0.6920.5400", test_version2: "3.0.6920.5468" ) || version_in_range( version: dllVer, test_version: "3.0.6920.8600", test_version2: "3.0.6920.8683" ) )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
sysPath = smb_get_systemroot();
if(sysPath){
	key = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\v3.0";
	if(registry_key_exists( key: key )){
		sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\XPSViewer\\XPSViewer.exe" );
		if(sysVer){
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: sysVer, test_version: "3.0.6920.4200", test_version2: "3.0.6920.4228" ) || version_in_range( version: sysVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.8683" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\4.0.30319.0";
if(registry_key_exists( key: key )){
	path = registry_get_sz( key: key, item: "Path" );
	if(path){
		dllv4 = fetch_file_version( sysPath: path, file_name: "WPF\\Presentationcore.dll" );
		if(dllv4){
			if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllv4, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1037" ) || version_in_range( version: dllv4, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2064" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
key = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\v3.0";
if(registry_key_exists( key: key )){
	path = registry_get_sz( key: key, item: "All Assemblies In" );
	if(path){
		predll = fetch_file_version( sysPath: path, file_name: "presentationcore.dll" );
		if(predll){
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "3.0.6920.8600", test_version2: "3.0.6920.8683" ) || version_in_range( version: dllVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.8007" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

