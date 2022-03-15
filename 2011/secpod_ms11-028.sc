if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902502" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-04-13 17:05:53 +0200 (Wed, 13 Apr 2011)" );
	script_cve_id( "CVE-2010-3958" );
	script_bugtraq_id( 47223 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft .NET Framework Remote Code Execution Vulnerability (2484015)" );
	script_xref( name: "URL", value: "http://support.microsoft.com/kb/2484015" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0945" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-028" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to crash an affected
  system or execute arbitrary code by tricking a user into visiting a specially
  crafted web page." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 4.0

  - Microsoft .NET Framework 2.0 Service Pack 2

  - Microsoft .NET Framework 3.5 Service Pack 1" );
	script_tag( name: "insight", value: "The flaw is caused by a stack corruption error in the x86 JIT compiler within
  the .NET Framework when compiling certain types of function calls, which
  could be exploited by remote attackers to execute arbitrary code by tricking
  a user into visiting a specially crafted web page." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-028." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win2008: 3, win7: 2 ) <= 0){
	exit( 0 );
}
if(( hotfix_missing( name: "2446704" ) == 0 ) || ( hotfix_missing( name: "2446708" ) == 0 ) || ( hotfix_missing( name: "2449741" ) == 0 ) || ( hotfix_missing( name: "2449742" ) == 0 ) || ( hotfix_missing( name: "2446709" ) == 0 ) || ( hotfix_missing( name: "2446710" ) == 0 )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "mscorlib.dll" );
		if(dllVer){
			if(hotfix_check_sp( xp: 4, win2003: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.200", test_version2: "4.0.30319.224" ) || version_in_range( version: dllVer, test_version: "4.0.30319.400", test_version2: "4.0.30319.430" ) || version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3619" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5000", test_version2: "2.0.50727.5652" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
				SP = get_kb_item( "SMB/WinVista/ServicePack" );
				if(!SP){
					SP = get_kb_item( "SMB/Win2008/ServicePack" );
				}
				if(ContainsString( SP, "Service Pack 1" )){
					if(version_in_range( version: dllVer, test_version: "4.0.30319.200", test_version2: "4.0.30319.224" ) || version_in_range( version: dllVer, test_version: "4.0.30319.400", test_version2: "4.0.30319.430" ) || version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3618" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5000", test_version2: "2.0.50727.5652" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
						exit( 0 );
					}
				}
				if(ContainsString( SP, "Service Pack 2" )){
					if(version_in_range( version: dllVer, test_version: "4.0.30319.200", test_version2: "4.0.30319.224" ) || version_in_range( version: dllVer, test_version: "4.0.30319.400", test_version2: "4.0.30319.430" ) || version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4210" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5000", test_version2: "2.0.50727.5652" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
						exit( 0 );
					}
				}
			}
			if(hotfix_check_sp( win7: 2 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.200", test_version2: "4.0.30319.224" ) || version_in_range( version: dllVer, test_version: "4.0.30319.400", test_version2: "4.0.30319.430" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5000", test_version2: "2.0.50727.5443" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5600", test_version2: "2.0.50727.5652" ) || version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4958" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}

