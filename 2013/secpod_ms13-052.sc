if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902985" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-3129", "CVE-2013-3131", "CVE-2013-3132", "CVE-2013-3133", "CVE-2013-3134", "CVE-2013-3171" );
	script_bugtraq_id( 60978, 60932, 60933, 60934, 60935, 60937 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-07-10 12:28:17 +0530 (Wed, 10 Jul 2013)" );
	script_name( "Microsoft .NET Framework Multiple Vulnerabilities (2861561)" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Microsoft Bulletin MS13-052." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "insight", value: "Multiple flaws due to:

  - Improper handling of TrueType font and multidimensional arrays of small
  structures

  - Improper validation of permissions for certain objects performing reflection
  and delegate objects during serialization" );
	script_tag( name: "affected", value: "Microsoft .NET Framework 1.0, 1.1, 2.0, 3.0, 3.5, 3.5.1, 4.0 and 4.5." );
	script_tag( name: "impact", value: "Successful exploitation could allow an attacker to execute arbitrary code,
  bypass security mechanism and take complete control of an affected system." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2861561" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2013/ms13-052" );
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
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "mscorlib.dll" );
		if(dllVer){
			if(version_in_range( version: dllVer, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1007" ) || version_in_range( version: dllVer, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2011" )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18051" ) || version_in_range( version: dllVer, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19079" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18050" ) || version_in_range( version: dllVer, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19078" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5471" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7024" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.6000", test_version2: "2.0.50727.6406" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7024" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4240" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7024" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3648" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7025" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( xp: 4, win2003: 3, win2003x64: 3, winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "1.1.4322.2000", test_version2: "1.1.4322.2502" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "System.configuration.dll" );
		if(dllVer){
			if(hotfix_check_sp( xp: 4, win2003: 3, win2003x64: 3, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3653" ) || version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4245" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7034" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.7036" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(hotfix_check_sp( win8: 1, win2012: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "2.0.50727.6400", test_version2: "2.0.50727.6410" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7034" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "2.0.50727.5400", test_version2: "2.0.50727.5475" ) || version_in_range( version: dllVer, test_version: "2.0.50727.7000", test_version2: "2.0.50727.7034" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( win8: 1, win2012: 1 ) > 0 )){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18057" ) || version_in_range( version: dllVer, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19111" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "System.printing.dll" );
		if(dllVer){
			if(hotfix_check_sp( win8: 1, win2012: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "3.0.6920.6400", test_version2: "3.0.6920.6401" ) || version_in_range( version: dllVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.7035" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "3.0.6920.5400", test_version2: "3.0.6920.5452" ) || version_in_range( version: dllVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.7035" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "System.Data.Linq.dll" );
		if(dllVer){
			if(hotfix_check_sp( xp: 4, win2003: 3, win2003x64: 3, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "3.5.30729.4000", test_version2: "3.5.30729.4051" ) || version_in_range( version: dllVer, test_version: "3.0.30729.7000", test_version2: "3.5.30729.7048" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(hotfix_check_sp( win8: 1, win2012: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "3.5.30729.6400", test_version2: "3.5.30729.6403" ) || version_in_range( version: dllVer, test_version: "3.5.30729.7000", test_version2: "3.5.30729.7047" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ) && ( version_in_range( version: dllVer, test_version: "3.5.30729.5400", test_version2: "3.5.30729.5454" ) || version_in_range( version: dllVer, test_version: "3.5.30729.7000", test_version2: "3.5.30729.7047" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
		}
	}
}
sysPath = smb_get_systemroot();
if(sysPath){
	key = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\v3.0";
	if(registry_key_exists( key: key )){
		sysVer = fetch_file_version( sysPath: sysPath, file_name: "system32\\XPSViewer\\XPSViewer.exe" );
		if(sysVer){
			if(( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ) && ( version_in_range( version: sysVer, test_version: "3.0.6920.4200", test_version2: "3.0.6920.4215" ) || version_in_range( version: sysVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.7035" ) )){
				security_message( port: 0, data: "The target host was found to be vulnerable" );
				exit( 0 );
			}
			if(( hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3 ) > 0 ) && ( version_in_range( version: sysVer, test_version: "3.0.6920.4000", test_version2: "3.0.6920.4049" ) || version_in_range( version: sysVer, test_version: "3.0.6920.7000", test_version2: "3.0.6920.7044" ) )){
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
	}
}
if(dllv4){
	if(hotfix_check_sp( xp: 4, win2003: 3, win2003x64: 3, winVista: 3, win2008: 3 ) > 0){
		if(version_in_range( version: dllv4, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1004" ) || version_in_range( version: dllv4, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2008" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
	if(hotfix_check_sp( xp: 4, win2003: 3, win2003x64: 3, winVista: 3, win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
		if(version_in_range( version: dllv4, test_version: "4.0.30319.1000", test_version2: "4.0.30319.1014" ) || version_in_range( version: dllv4, test_version: "4.0.30319.2000", test_version2: "4.0.30319.2021" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
	if(( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0 ) && version_in_range( version: dllv4, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18059" ) || version_in_range( version: dllv4, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19114" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\4.0.30319.0";
if(registry_key_exists( key: key )){
	path = registry_get_sz( key: key, item: "Path" );
	if(path){
		dllv4 = fetch_file_version( sysPath: path, file_name: "WPF\\Wpftxt_v0400.dll" );
	}
}
if(!dllv4){
	exit( 0 );
}
if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
	if(version_in_range( version: dllv4, test_version: "4.0.30319.18000", test_version2: "4.0.30319.18048" ) || version_in_range( version: dllv4, test_version: "4.0.30319.19000", test_version2: "4.0.30319.19076" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

