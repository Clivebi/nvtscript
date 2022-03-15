if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811827" );
	script_version( "2021-09-14T12:01:45+0000" );
	script_cve_id( "CVE-2017-8759" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 12:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-14 02:29:00 +0000 (Sun, 14 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-09-14 10:52:54 +0530 (Thu, 14 Sep 2017)" );
	script_name( "Microsoft .NET Framework Remote Code Execution Vulnerability (KB4040973)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Security Updates KB4040973." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists as when Microsoft .NET Framework
  processes untrusted input." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to take control of an affected system. An attacker could then install
  programs, view, change, or delete data, or create new accounts with full user
  rights. Users whose accounts are configured to have fewer user rights on the
  system could be less impacted than users who operate with administrative user
  rights." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 4.6/4.6.1

  - Microsoft .NET Framework 4.6.2

  - Microsoft .NET Framework 4.7" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4040973" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008: 3, win7: 2, win7x64: 2, win2008r2: 2 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	dotPath = registry_get_sz( key: key + item, item: "Path" );
	if(dotPath && ContainsString( dotPath, "\\Microsoft.NET\\Framework" )){
		sysdllVer = fetch_file_version( sysPath: dotPath, file_name: "system.dll" );
		if(!sysdllVer){
			exit( 0 );
		}
		if( hotfix_check_sp( win2008: 3 ) > 0 ){
			key1 = "SOFTWARE\\Microsoft\\NET Framework Setup\\NDP\\v4\\Client\\";
			brkVer = registry_get_sz( key: key1, item: "Version" );
			if(( brkVer == "4.6.00081" ) && IsMatchRegexp( sysdllVer, "(^4\\.6)" )){
				if(version_is_less( version: sysdllVer, test_version: "4.7.2113" )){
					VULN = TRUE;
				}
			}
		}
		else {
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 && version_in_range( version: sysdllVer, test_version: "4.6", test_version2: "4.7.2113" )){
				VULN = TRUE;
			}
		}
		if(VULN){
			report = "File checked:     " + dotPath + "system.dll" + "\n" + "File version:     " + sysdllVer + "\n" + "Vulnerable range: 4.6 - 4.7.2113\n";
			security_message( data: report );
			exit( 0 );
		}
	}
}

