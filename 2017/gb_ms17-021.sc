if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810596" );
	script_version( "2021-09-17T08:01:48+0000" );
	script_cve_id( "CVE-2017-0042" );
	script_bugtraq_id( 96098 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 08:01:48 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-12 01:29:00 +0000 (Wed, 12 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-15 12:30:19 +0530 (Wed, 15 Mar 2017)" );
	script_name( "Microsoft Windows DirectShow Information Disclosure Vulnerability (4010318)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS17-021." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists when windows DirectShow
  handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow an attacker
  to obtain information to further compromise a target system." );
	script_tag( name: "affected", value: "- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Vista x32/x64 Edition Service Pack 2

  - Microsoft Windows Server 2008 x32/x64 Edition Service Pack 2

  - Microsoft Windows 7 x32/x64 Edition Service Pack 1

  - Microsoft Windows Server 2008 R2 x64 Edition Service Pack 1

  - Microsoft Windows Server 2016" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/4010318" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS17-021" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, winVistax64: 3, win2008x64: 3, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1, win2016: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
qzVer = fetch_file_version( sysPath: sysPath, file_name: "Quartz.dll" );
gdiVer = fetch_file_version( sysPath: sysPath, file_name: "Gdi32.dll" );
if(!qzVer && !gdiVer){
	exit( 0 );
}
if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 && qzVer ){
	if(version_is_less( version: qzVer, test_version: "6.6.7601.23643" )){
		Vulnerable_range1 = "Less than 6.6.7601.23643";
		VULN1 = TRUE;
	}
}
else {
	if( hotfix_check_sp( winVista: 3, winVistax64: 3, win2008: 3, win2008x64: 3 ) > 0 && qzVer ){
		if( version_is_less( version: qzVer, test_version: "6.6.6002.19725" ) ){
			Vulnerable_range1 = "Less than 6.6.6002.19725";
			VULN1 = TRUE;
		}
		else {
			if(version_in_range( version: qzVer, test_version: "6.6.6002.24000", test_version2: "6.6.6002.24047" )){
				Vulnerable_range1 = "6.6.6002.24000 - 6.6.6002.24047";
				VULN1 = TRUE;
			}
		}
	}
	else {
		if( hotfix_check_sp( win2012: 1 ) > 0 && gdiVer ){
			if(version_is_less( version: gdiVer, test_version: "6.2.9200.22120" )){
				Vulnerable_range = "Less than 6.2.9200.22120";
				VULN = TRUE;
			}
		}
		else {
			if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 && qzVer ){
				if(version_is_less( version: qzVer, test_version: "6.6.9600.18569" )){
					Vulnerable_range1 = "Less than 6.6.9600.18569";
					VULN1 = TRUE;
				}
			}
			else {
				if( hotfix_check_sp( win10: 1, win10x64: 1 ) > 0 && gdiVer ){
					if( version_is_less( version: gdiVer, test_version: "10.0.10240.17319" ) ){
						Vulnerable_range = "Less than 10.0.10240.17319";
						VULN = TRUE;
					}
					else {
						if( version_in_range( version: gdiVer, test_version: "10.0.10586.0", test_version2: "10.0.10586.838" ) ){
							Vulnerable_range = "10.0.10586.0 - 10.0.10586.838";
							VULN = TRUE;
						}
						else {
							if(version_in_range( version: gdiVer, test_version: "10.0.14393.0", test_version2: "10.0.14393.205" )){
								Vulnerable_range = "10.0.14393.0 - 10.0.14393.205";
								VULN = TRUE;
							}
						}
					}
				}
				else {
					if(hotfix_check_sp( win2016: 1 ) > 0 && gdiVer){
						if(version_in_range( version: gdiVer, test_version: "10.0.14393.0", test_version2: "10.0.14393.205" )){
							Vulnerable_range = "10.0.14393.0 - 10.0.14393.205";
							VULN = TRUE;
						}
					}
				}
			}
		}
	}
}
if( VULN ){
	report = "File checked:     " + sysPath + "\\Gdi32.dll" + "\n" + "File version:     " + gdiVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
else {
	if(VULN1){
		report = "File checked:     " + sysPath + "\\Quartz.dll" + "\n" + "File version:     " + qzVer + "\n" + "Vulnerable range: " + Vulnerable_range1 + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

