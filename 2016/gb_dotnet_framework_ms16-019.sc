if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806681" );
	script_version( "2020-06-08T14:40:48+0000" );
	script_cve_id( "CVE-2016-0033", "CVE-2016-0047" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2020-06-08 14:40:48 +0000 (Mon, 08 Jun 2020)" );
	script_tag( name: "creation_date", value: "2016-02-10 10:38:07 +0530 (Wed, 10 Feb 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft .NET Framework Denial of Service Vulnerabilities (3137893)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-019." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist as,

  - Application fails to properly handle certain Extensible Stylesheet
    Language Transformations (XSLT).

  - The .NET's Windows Forms (WinForms) improperly handles icon data." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to sensitive information or disrupt the availability of
  applications that use the .NET framework." );
	script_tag( name: "affected", value: "- Microsoft .NET Framework 2.0 Service Pack 2

  - Microsoft .NET Framework 3.5

  - Microsoft .NET Framework 3.5.1

  - Microsoft .NET Framework 4.5.2

  - Microsoft .NET Framework 4.6 and 4.6.1" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3137893" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-019" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
key = "SOFTWARE\\Microsoft\\ASP.NET\\";
if(!registry_key_exists( key: key )){
	exit( 0 );
}
for item in registry_enum_keys( key: key ) {
	path = registry_get_sz( key: key + item, item: "Path" );
	if(path && ContainsString( path, "\\Microsoft.NET\\Framework" )){
		dllVer = fetch_file_version( sysPath: path, file_name: "System.Xml.dll" );
		dllVer2 = fetch_file_version( sysPath: path, file_name: "System.Drawing.dll" );
		if(dllVer || dllVer2){
			if(hotfix_check_sp( winVista: 3, win2008: 3 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.4260" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.4260";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8678" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.5700 - 2.0.50727.8678";
				}
				if(version_is_less( version: dllVer2, test_version: "2.0.50727.4261" )){
					VULN2 = TRUE;
					vulnerable_range = "Less than 2.0.50727.4261";
				}
				if(version_in_range( version: dllVer2, test_version: "2.0.50727.5700", test_version2: "2.0.50727.8680" )){
					VULN2 = TRUE;
					vulnerable_range = "2.0.50727.5700 - 2.0.50727.8680";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.5494" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.5494";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8678" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8600 - 2.0.50727.8678";
				}
				if(version_is_less( version: dllVer2, test_version: "2.0.50727.5495" )){
					VULN2 = TRUE;
					vulnerable_range = "Less than 2.0.50727.5495";
				}
				if(version_in_range( version: dllVer2, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8680" )){
					VULN2 = TRUE;
					vulnerable_range = "2.0.50727.5700 - 2.0.50727.8680";
				}
			}
			if(hotfix_check_sp( win2012: 1 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.6430" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.6430";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8000", test_version2: "2.0.50727.8678" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8000 - 2.0.50727.8678";
				}
				if(version_is_less( version: dllVer2, test_version: "2.0.50727.6431" )){
					VULN2 = TRUE;
					vulnerable_range = "Less than 2.0.50727.6431";
				}
				if(version_in_range( version: dllVer2, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8680" )){
					VULN2 = TRUE;
					vulnerable_range = "2.0.50727.5700 - 2.0.50727.8680";
				}
			}
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.8018" )){
					VULN1 = TRUE;
					vulnerable_range = "Less than 2.0.50727.8018";
				}
				if(version_in_range( version: dllVer, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8678" )){
					VULN1 = TRUE;
					vulnerable_range = "2.0.50727.8600 - 2.0.50727.8678";
				}
				if(version_is_less( version: dllVer2, test_version: "2.0.50727.8019" )){
					VULN2 = TRUE;
					vulnerable_range = "Less than 2.0.50727.8019";
				}
				if(version_in_range( version: dllVer2, test_version: "2.0.50727.8600", test_version2: "2.0.50727.8680" )){
					VULN2 = TRUE;
					vulnerable_range = "2.0.50727.5700 - 2.0.50727.8680";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34282" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34282";
				}
				if(version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36335" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36335";
				}
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34284" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34284";
				}
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36337" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36337";
				}
			}
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1, win2012: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34280" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34280";
				}
				if(version_in_range( version: dllVer, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36333" )){
					VULN1 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36333";
				}
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.30000", test_version2: "4.0.30319.34283" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.30000 - 4.0.30319.34283";
				}
				if(version_in_range( version: dllVer2, test_version: "4.0.30319.36000", test_version2: "4.0.30319.36336" )){
					VULN2 = TRUE;
					vulnerable_range = "4.0.30319.36000 - 4.0.30319.36336";
				}
			}
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.1066" )){
					VULN1 = TRUE;
					vulnerable_range = "4.6 - 4.6.1066";
				}
			}
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1, win2012: 1 ) > 0){
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.1064.1" )){
					VULN1 = TRUE;
					vulnerable_range = "4.6 - 4.6.1064.1";
				}
				if(version_in_range( version: dllVer2, test_version: "4.6", test_version2: "4.6.1068.1" )){
					VULN2 = TRUE;
					vulnerable_range = "4.6 - 4.6.1068.1";
				}
			}
			if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
				if(version_is_less( version: dllVer, test_version: "2.0.50727.8679" )){
					vulnerable_range = "Less than 2.0.50727.8679";
					VULN1 = TRUE;
				}
				if(version_in_range( version: dllVer, test_version: "4.6", test_version2: "4.6.1064.1" )){
					VULN1 = TRUE;
					vulnerable_range = "4.6 - 4.6.1064.1";
				}
				if(version_is_less( version: dllVer2, test_version: "2.0.50727.8681" )){
					vulnerable_range = "Less than 2.0.50727.8681";
					VULN2 = TRUE;
				}
				if(version_in_range( version: dllVer2, test_version: "4.6", test_version2: "4.6.1068.1" )){
					VULN2 = TRUE;
					vulnerable_range = "4.6 - 4.6.1068.1";
				}
			}
		}
		dllVer3 = fetch_file_version( sysPath: path, file_name: "\\SetupCache\\v4.6.00081\\SetupUi.dll" );
		if(dllVer3){
			if(hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, winVista: 3, win2008: 3 ) > 0){
				if(version_is_less( version: dllVer3, test_version: "14.0.1068.2" )){
					VULN3 = TRUE;
					vulnerable_range = "Less than 14.0.1068.2";
				}
			}
		}
	}
}
if(VULN1){
	report = "File checked:     " + path + "System.Xml.dll" + "\n" + "File version:     " + dllVer + "\n" + "Vulnerable range: " + vulnerable_range + "\n";
	security_message( data: report );
}
if(VULN2){
	report = "File checked:     " + path + "System.Drawing.dll" + "\n" + "File version:     " + dllVer2 + "\n" + "Vulnerable range: " + vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
if(VULN3){
	report = "File checked:     " + path + "\\SetupCache\\v4.6.00081\\SetupUi.dll" + "\n" + "File version:     " + dllVer3 + "\n" + "Vulnerable range: " + vulnerable_range + "\n";
	security_message( data: report );
}

