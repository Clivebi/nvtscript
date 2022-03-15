if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903308" );
	script_version( "2021-08-05T12:20:54+0000" );
	script_cve_id( "CVE-2013-1336", "CVE-2013-1337" );
	script_bugtraq_id( 59789, 59790 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-05 12:20:54 +0000 (Thu, 05 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-05-15 12:23:29 +0530 (Wed, 15 May 2013)" );
	script_name( "Microsoft .NET Framework Authentication Bypass and Spoofing Vulnerabilities (2836440)" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-040" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to bypass security mechanism
  and gain access to restricted endpoint functions." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 4

  - Microsoft .NET Framework 4.5

  - Microsoft .NET Framework 3.5

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 2.0 Service Pack 2" );
	script_tag( name: "insight", value: "The flaws are due to

  - Improper validation of XML signatures by the CLR

  - Error within the WCF endpoint authentication mechanism when handling
    queries" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-040." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win2012: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(registry_key_exists( key: key )){
	for item in registry_enum_keys( key: key ) {
		path = registry_get_sz( key: key + item, item: "Path" );
		if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
			dllVer = fetch_file_version( sysPath: path, file_name: "System.Security.dll" );
			if(dllVer && ( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18038" ) || version_in_range( version: dllVer, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19057" ) || version_in_range( version: dllVer, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6403" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7017" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(dllVer && ( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "2.0.50727.5000", test_version2: "2.0.50727.5468" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7017" ) || version_in_range( version: dllVer, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1003" ) || version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2005" ) || version_in_range( version: dllVer, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18037" ) || version_in_range( version: dllVer, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19056" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(dllVer && ( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "2.0.50727.0000", test_version2: "2.0.50727.4236" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7017" ) || version_in_range( version: dllVer, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1003" ) || version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2005" ) || version_in_range( version: dllVer, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18037" ) || version_in_range( version: dllVer, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19056" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(dllVer && ( hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1003" ) || version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2005" ) || version_in_range( version: dllVer, test_version: "2.0.50727.0000", test_version2: "2.0.50727.3645" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7018" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

