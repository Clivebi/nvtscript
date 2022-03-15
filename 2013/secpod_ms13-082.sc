if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903412" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-3128", "CVE-2013-3860", "CVE-2013-3861" );
	script_bugtraq_id( 62819, 62820, 62807 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-10-09 12:14:29 +0530 (Wed, 09 Oct 2013)" );
	script_name( "Microsoft .NET Framework Remote Code Execution Vulnerabilities (2878890)" );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS13-082." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An unspecified error when handling OpenType fonts (OTF).

  - An error when when expanding entity references.

  - An unspecified error when parsing JSON data." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 2.x

  - Microsoft .NET Framework 3.x

  - Microsoft .NET Framework 4.x" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to execute the arbitrary
  code, exhaust available system resource, cause a DoS (Denial of Service) and compromise the system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2878890" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-082" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win2012: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(registry_key_exists( key: key )){
	for item in registry_enum_keys( key: key ) {
		path = registry_get_sz( key: key + item, item: "Path" );
		if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
			dllVer = fetch_file_version( sysPath: path, file_name: "System.Security.dll" );
			if(dllVer && ( hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1015" ) || version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2025" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(dllVer && ( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18055" ) || version_in_range( version: dllVer, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19108" ) || version_in_range( version: dllVer, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6409" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7031" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(dllVer && ( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18054" ) || version_in_range( version: dllVer, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19107" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(( dllVer && hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5474" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7031" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(dllVer && ( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4244" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7031" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(dllVer && ( hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3651" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7031" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\4.0.30319.0";
if(registry_key_exists( key: key )){
	path = registry_get_sz( key: key, item: "Path" );
	if(path){
		dllv4 = fetch_file_version( sysPath: path, file_name: "WPF\\Wpftxt_v0400.dll" );
	}
	if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
		if(version_in_range( version: dllv4, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18058" ) || version_in_range( version: dllv4, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19113" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
	if(hotfix_check_sp( xp: 4, win2003: 3, win2003x64: 3, winVista: 3, win2008: 3 ) > 0){
		if(version_in_range( version: dllv4, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1013" ) || version_in_range( version: dllv4, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2020" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
sysPath = smb_get_systemroot();
if(sysPath){
	dllVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\presentationcffrasterizernative_v0300.dll" );
	if(dllVer && ( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 )){
		if(version_in_range( version: dllVer, test_version: "3.0.6920.4000", test_version2: "3.0.6920.4217" ) || version_in_range( version: dllVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.7061" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
	if(( dllVer && hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 )){
		if(version_in_range( version: dllVer, test_version: "3.0.6920.5000", test_version2: "3.0.6920.5458" ) || version_in_range( version: dllVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.7061" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
	if(dllVer && ( hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) > 0 )){
		if(version_in_range( version: dllVer, test_version: "3.0.6920.4000", test_version2: "3.0.6920.4057" ) || version_in_range( version: dllVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.7060" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
	if(dllVer && ( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 )){
		if(version_in_range( version: dllVer, test_version: "3.0.6920.6000", test_version2: "3.0.6920.6408" ) || version_in_range( version: dllVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.7061" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
key = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\v3.5";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
path = registry_get_sz( key: key, item: "All Assemblies In" );
if(!path){
	exit( 0 );
}
dllv3 = fetch_file_version( sysPath: path, file_name: "System.Web.Extensions.dll" );
if(!dllv3){
	exit( 0 );
}
if(dllv3 && ( hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win2008: 3 ) > 0 )){
	if(version_in_range( version: dllv3, test_version: "3.5.30729.4000", test_version2: "3.5.30729.4055" ) || version_in_range( version: dllv3, test_version: "3.5.30729.7000", test_version2: "3.5.30729.7055" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
if(dllv3 && ( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 )){
	if(version_in_range( version: dllv3, test_version: "3.5.30729.4000", test_version2: "3.5.30729.6406" ) || version_in_range( version: dllv3, test_version: "3.5.30729.7000", test_version2: "3.5.30729.7056" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
if(( dllv3 && hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 )){
	if(version_in_range( version: dllv3, test_version: "3.5.30729.5000", test_version2: "3.5.30729.5457" ) || version_in_range( version: dllv3, test_version: "3.5.30729.7000", test_version2: "3.5.30729.7056" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

