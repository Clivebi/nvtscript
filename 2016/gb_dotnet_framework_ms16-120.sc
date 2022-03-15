if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809706" );
	script_version( "2019-12-20T10:24:46+0000" );
	script_cve_id( "CVE-2016-3209" );
	script_bugtraq_id( 93385 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-12-20 10:24:46 +0000 (Fri, 20 Dec 2019)" );
	script_tag( name: "creation_date", value: "2016-10-12 13:56:09 +0530 (Wed, 12 Oct 2016)" );
	script_name( "Microsoft .NET Framework Information Disclosure Vulnerability (3192884)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-120." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to error in the way that the
  Windows Graphics Device Interface (GDI) handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 3.0 Service Pack 2

  - Microsoft .NET Framework 4.5.2

  - Microsoft .NET Framework 4.6

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 3.5" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3192884" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-120" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, winVistax64: 3, win7: 2, win7x64: 2, win2008: 3, win2008x64: 3, win2008r2: 2, win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\.NETFramework\\AssemblyFolders\\v3.0";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
path = registry_get_sz( key: key, item: "All Assemblies In" );
if(path){
	dllVer = fetch_file_version( sysPath: path, file_name: "System.printing.dll" );
}
if(dllVer){
	if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win2012: 1, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
		if(version_in_range( version: dllVer, test_version: "3.0", test_version2: "3.0.6920.8719" )){
			VULN1 = TRUE;
			vulnerable_range1 = "3.0 - 3.0.6920.8719";
		}
	}
	else {
		if(hotfix_check_sp( winVista: 3, winVistax64: 3, win2008: 3, win2008x64: 3 ) > 0){
			if(version_in_range( version: dllVer, test_version: "3.0", test_version2: "3.0.6920.8719" )){
				VULN1 = TRUE;
				vulnerable_range1 = "3.0 - 3.0.6920.8719";
			}
		}
	}
}
key = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Client\\";
if(registry_key_exists( key: key )){
	pathv45 = registry_get_sz( key: key, item: "InstallPath" );
	if(pathv45){
		dllv45 = fetch_file_version( sysPath: pathv45, file_name: "WPF\\wpfgfx_v0400.dll" );
		if(dllv45){
			if(hotfix_check_sp( winVista: 3, winVistax64: 3, win2008: 3, win2008x64: 3 ) > 0){
				if(version_in_range( version: dllv45, test_version: "4.0", test_version2: "4.0.30319.36366" )){
					VULN2 = TRUE;
					vulnerable_range2 = "4.0 - 4.0.30319.36366";
				}
			}
		}
		dfdllVer = fetch_file_version( sysPath: pathv45, file_name: "dfdll.dll" );
		if(dfdllVer){
			if(hotfix_check_sp( winVista: 3, winVistax64: 3, win2008: 3, win2008x64: 3 ) > 0){
				if(version_in_range( version: dfdllVer, test_version: "4.6", test_version2: "4.6.1084" )){
					VULN3 = TRUE;
					vulnerable_range3 = "4.6 - 4.6.1084";
				}
			}
		}
	}
}
edgeVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0 && edgeVer){
	if( version_is_less( version: edgeVer, test_version: "11.0.10240.17146" ) ){
		vulnerable_range4 = "Less than 11.0.10240.17146";
		VULN4 = TRUE;
	}
	else {
		if( version_in_range( version: edgeVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.632" ) ){
			vulnerable_range4 = "11.0.10586.0 - 11.0.10586.632";
			VULN4 = TRUE;
		}
		else {
			if(version_in_range( version: edgeVer, test_version: "11.0.14393.0", test_version2: "11.0.14393.320" )){
				vulnerable_range4 = "11.0.14393.0 - 11.0.14393.320";
				VULN4 = TRUE;
			}
		}
	}
}
if( VULN1 ){
	report = "File checked:     " + path + "System.printing.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + vulnerable_range1 + "\n";
	security_message( data: report );
	exit( 0 );
}
else {
	if( VULN2 ){
		report = "File checked:     " + pathv45 + "WPF\\wpfgfx_v0400.dll" + "\n" + "File version:     " + dllv45 + "\n" + "Vulnerable range: " + vulnerable_range2 + "\n";
		security_message( data: report );
		exit( 0 );
	}
	else {
		if( VULN3 ){
			report = "File checked:     " + pathv45 + "dfdll.dll" + "\n" + "File version:     " + dfdllVer + "\n" + "Vulnerable range: " + vulnerable_range3 + "\n";
			security_message( data: report );
			exit( 0 );
		}
		else {
			if(VULN4){
				report = "File checked:     " + sysPath + "\\edgehtml.dll" + "\n" + "File version:     " + edgeVer + "\n" + "Vulnerable range: " + vulnerable_range4 + "\n";
				security_message( data: report );
				exit( 0 );
			}
		}
	}
}
exit( 0 );

