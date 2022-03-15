if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902581" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-10-12 16:01:32 +0200 (Wed, 12 Oct 2011)" );
	script_cve_id( "CVE-2011-1253" );
	script_bugtraq_id( 49999 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "Microsoft .NET Framework and Silverlight Remote Code Execution Vulnerability (2604930)" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026161" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1026162" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2011/ms11-078" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "secpod_reg_enum.sc", "gb_ms_silverlight_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/registry_enumerated" );
	script_tag( name: "impact", value: "Successful exploitation could allow attacker to execute arbitrary code within
  the context of the affected application. Failed exploit attempts will likely
  result in a denial-of-service condition." );
	script_tag( name: "affected", value: "- Microsoft Silverlight 4.0

  - Microsoft .NET Framework 4.0

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 2.0 Service Pack 2

  - Microsoft .NET Framework 1.1 Service Pack 1" );
	script_tag( name: "insight", value: "The flaw due to an error when restricting inheritance within classes
  and can be exploited via a specially crafted web page." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "summary", value: "This host is missing a critical security update according to
  Microsoft Bulletin MS11-078." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
require("host_details.inc.sc");
if(hotfix_check_sp( xp: 4, win2003: 3, winVista: 3, win2008: 3, win7: 2 ) <= 0){
	exit( 0 );
}
if(( hotfix_missing( name: "2572078" ) == 0 ) && ( hotfix_missing( name: "2572077" ) == 0 ) && ( hotfix_missing( name: "2572076" ) == 0 ) && ( hotfix_missing( name: "2572075" ) == 0 ) && ( hotfix_missing( name: "2572073" ) == 0 ) && ( hotfix_missing( name: "2572069" ) == 0 ) && ( hotfix_missing( name: "2572067" ) == 0 ) && ( hotfix_missing( name: "2572066" ) == 0 ) && ( hotfix_missing( name: "2617986" ) == 0 )){
	exit( 0 );
}
if(infos = get_app_version_and_location( cpe: "cpe:/a:microsoft:silverlight", exit_no_version: FALSE )){
	mslVers = infos["version"];
	mslPath = infos["location"];
	if(mslVers){
		if(version_is_less( version: mslVers, test_version: "4.0.60831" )){
			report = report_fixed_ver( installed_version: mslVers, fixed_version: "4.0.60831", install_path: mslPath );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
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
			if(hotfix_check_sp( win2003: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "1.1.4322.2000", test_version2: "1.1.4322.2489" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(hotfix_check_sp( xp: 4, win2003: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.000", test_version2: "4.0.30319.238" ) || version_in_range( version: dllVer, test_version: "4.0.30319.400", test_version2: "4.0.30319.487" ) || version_in_range( version: dllVer, test_version: "2.0.50727.3000", test_version2: "2.0.50727.3624" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5000", test_version2: "2.0.50727.5680" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
			if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
				SP = get_kb_item( "SMB/WinVista/ServicePack" );
				if(!SP){
					SP = get_kb_item( "SMB/Win2008/ServicePack" );
				}
				if(ContainsString( SP, "Service Pack 2" )){
					if(version_in_range( version: dllVer, test_version: "4.0.30319.000", test_version2: "4.0.30319.238" ) || version_in_range( version: dllVer, test_version: "4.0.30319.400", test_version2: "4.0.30319.487" ) || version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4215" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5000", test_version2: "2.0.50727.5680" ) || version_in_range( version: dllVer, test_version: "1.1.4322.2000", test_version2: "1.1.4322.2489" )){
						security_message( port: 0, data: "The target host was found to be vulnerable" );
						exit( 0 );
					}
				}
			}
			if(hotfix_check_sp( win7: 2 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.000", test_version2: "4.0.30319.238" ) || version_in_range( version: dllVer, test_version: "4.0.30319.400", test_version2: "4.0.30319.487" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5000", test_version2: "2.0.50727.5447" ) || version_in_range( version: dllVer, test_version: "2.0.50727.5600", test_version2: "2.0.50727.5680" ) || version_in_range( version: dllVer, test_version: "2.0.50727.4000", test_version2: "2.0.50727.4962" )){
					security_message( port: 0, data: "The target host was found to be vulnerable" );
					exit( 0 );
				}
			}
		}
	}
}
exit( 99 );

