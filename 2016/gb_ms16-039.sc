if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806699" );
	script_version( "2021-09-20T14:01:48+0000" );
	script_cve_id( "CVE-2016-0143", "CVE-2016-0145", "CVE-2016-0165", "CVE-2016-0167" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 14:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-04-13 10:31:53 +0530 (Wed, 13 Apr 2016)" );
	script_name( "Microsoft Graphics Component Multiple Vulnerabilities (3148522)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-039." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in kernel-mode driver which fails to properly handle objects in memory.

  - An error in windows font library which improperly handles specially crafted
  embedded fonts." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code and gain elevated privileges on the
  affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3148522" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-039" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_reg_service_pack.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "SMB/WindowsVersion" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/en-us/library/security/MS16-039" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
winPath = smb_get_systemroot();
if(!winPath){
	exit( 0 );
}
windllVer = fetch_file_version( sysPath: winPath, file_name: "System32\\Win32k.sys" );
if(!windllVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	if( version_is_less( version: windllVer, test_version: "6.0.6002.19626" ) ){
		Vulnerable_range = "Less than 6.0.6002.19626";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: windllVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23942" )){
			Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23942";
			VULN = TRUE;
		}
	}
}
else {
	if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
		if(version_is_less( version: windllVer, test_version: "6.3.9600.18290" )){
			Vulnerable_range = "Less than 6.3.9600.18290";
			VULN = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
			if(version_is_less( version: windllVer, test_version: "6.1.7601.23407" )){
				Vulnerable_range = "Less than 6.1.7601.23407";
				VULN = TRUE;
			}
		}
		else {
			if( hotfix_check_sp( win2012: 1 ) > 0 ){
				if(version_is_less( version: windllVer, test_version: "6.2.9200.21824" )){
					Vulnerable_range = "Less than 6.2.9200.21824";
					VULN = TRUE;
				}
			}
			else {
				if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
					if( version_is_less( version: windllVer, test_version: "10.0.10240.16384" ) ){
						Vulnerable_range = "Less than 10.0.10240.16384";
						VULN = TRUE;
					}
					else {
						if(version_in_range( version: windllVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.19" )){
							Vulnerable_range = "10.0.10586.0 - 10.0.10586.19";
							VULN = TRUE;
						}
					}
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + winPath + "\\System32\\Win32k.sys" + "\n" + "File version:     " + windllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

