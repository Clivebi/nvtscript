if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902833" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_bugtraq_id( 53356, 53357 );
	script_cve_id( "CVE-2012-0160", "CVE-2012-0161" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-05-09 16:16:16 +0530 (Wed, 09 May 2012)" );
	script_name( "Microsoft .NET Framework Remote Code Execution Vulnerability (2693777)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2693777" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1027036" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2012/ms12-035" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary code
  with the privileges of the currently logged-in user. Failed attacks will cause denial-of-service conditions." );
	script_tag( name: "affected", value: "Microsoft .NET Framework 1.0 SP3, 1.1 SP1, 2.0 SP2, 3.0 SP2, 3.5 SP1, 3.5.1, and 4." );
	script_tag( name: "insight", value: "The flaws are due to

  - An error within the .NET Framework does not properly serialize user input
  and can be exploited to treat untrusted input as trusted.

  - An error within the .NET Framework does not properly handle exceptions when
  serializing objects and can be exploited via partially trusted assemblies." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS12-035." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) <= 0){
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
			if(version_in_range( version: dllVer, test_version: "4.0.30319.000", test_version2: "4.0.30319.268" ) || version_in_range( version: dllVer, test_version: "4.0.30319.500", test_version2: "4.0.30319.543" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.5000", test_version2: "2.0.50727.5455" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5600", test_version2: "2.0.50727.5709" ) || version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4970" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4222" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.5709" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3633" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.5709" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( xp: 4, win2003: 3, win2003x64: 3, winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "1.1.4322.2000", test_version2: "1.1.4322.2493" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
sysPath = smb_get_systemroot();
if(!sysPath){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\v3.0";
if(registry_key_exists( key: key )){
	sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\XPSViewer\\XPSViewer.exe" );
	if(sysVer){
		if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: sysVer, test_version: "3.0.6920.0", test_version2: "3.0.6920.4205" ) || version_in_range( version: sysVer, test_version: "3.0.6920.5000", test_version2: "3.0.6920.5737" ) )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
		if(( hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: sysVer, test_version: "3.0.6920.0", test_version2: "3.0.6920.4020" ) || version_in_range( version: sysVer, test_version: "3.0.6920.5000", test_version2: "3.0.6920.5809" ) )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}

