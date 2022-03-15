if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810810" );
	script_version( "2021-09-16T12:01:45+0000" );
	script_cve_id( "CVE-2017-0143", "CVE-2017-0144", "CVE-2017-0145", "CVE-2017-0146", "CVE-2017-0147", "CVE-2017-0148" );
	script_bugtraq_id( 96703, 96704, 96705, 96707, 96709, 96706 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 12:01:45 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-21 01:29:00 +0000 (Thu, 21 Jun 2018)" );
	script_tag( name: "creation_date", value: "2017-03-15 09:07:19 +0530 (Wed, 15 Mar 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows SMB Server Multiple Vulnerabilities (4013389)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS17-010(WannaCrypt)" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to the way that the
  Microsoft Server Message Block 1.0 (SMBv1) server handles certain
  requests(WannaCrypt)." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to  gain the ability to execute code on the target server, also could
  lead to information disclosure from the server." );
	script_tag( name: "affected", value: "- Microsoft Windows 2003 x32/x64 Service Pack 2 and prior

  - Microsoft Windows XP SP2 x64

  - Microsoft Windows XP SP3 x86

  - Microsoft Windows 8 x86/x64

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows Server 2016

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/4013078" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS17-010" );
	script_xref( name: "URL", value: "http://www.catalog.update.microsoft.com/Search.aspx?q=KB4012598" );
	script_xref( name: "URL", value: "https://blogs.technet.microsoft.com/msrc/2017/05/12/customer-guidance-for-wannacrypt-attacks" );
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
if(hotfix_check_sp( xp: 4, xpx64: 3, win2003: 3, win2003x64: 3, win8: 1, win8x64: 1, winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, winVistax64: 3, win2008x64: 3, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1, win2016: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
vistVer = fetch_file_version( sysPath: sysPath, file_name: "drivers\\srv.sys" );
if(vistVer){
	if( hotfix_check_sp( winVista: 3, winVistax64: 3, win2008: 3, win2008x64: 3 ) > 0 ){
		if( version_is_less( version: vistVer, test_version: "6.0.6002.19743" ) ){
			Vulnerable_range1 = "Less than 6.0.6002.19743";
			VULN1 = TRUE;
		}
		else {
			if(version_in_range( version: vistVer, test_version: "6.0.6002.22000", test_version2: "6.0.6002.24066" )){
				Vulnerable_range1 = "6.0.6002.22000 - 6.0.6002.24066";
				VULN1 = TRUE;
			}
		}
	}
	else {
		if( hotfix_check_sp( xp: 4 ) > 0 ){
			if(version_is_less( version: vistVer, test_version: "5.1.2600.7208" )){
				Vulnerable_range1 = "Less than 5.1.2600.7208";
				VULN1 = TRUE;
			}
		}
		else {
			if( hotfix_check_sp( win2003: 3, win2003x64: 3, xpx64: 3 ) > 0 ){
				if(version_is_less( version: vistVer, test_version: "5.2.3790.6021" )){
					Vulnerable_range1 = "Less than 5.2.3790.6021";
					VULN1 = TRUE;
				}
			}
			else {
				if(hotfix_check_sp( win8: 1, win8x64: 1 ) > 0){
					if(version_is_less( version: vistVer, test_version: "6.2.9200.22099" )){
						Vulnerable_range1 = "Less than 6.2.9200.22099";
						VULN1 = TRUE;
					}
				}
			}
		}
	}
	if(VULN1){
		report = "File checked:     " + sysPath + "\\drivers\\srv.sys" + "\n" + "File version:     " + vistVer + "\n" + "Vulnerable range: " + Vulnerable_range1 + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
winVer = fetch_file_version( sysPath: sysPath, file_name: "Win32k.sys" );
if(winVer){
	if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 && winVer ){
		if(version_is_less( version: winVer, test_version: "6.1.7601.23677" )){
			Vulnerable_range = "Less than 6.1.7601.23677";
			VULN = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( win2012: 1 ) > 0 ){
			if(version_is_less( version: winVer, test_version: "6.2.9200.22097" )){
				Vulnerable_range = "Less than 6.2.9200.22097";
				VULN = TRUE;
			}
		}
		else {
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_is_less( version: winVer, test_version: "6.3.9600.18603" )){
					Vulnerable_range = "Less than 6.3.9600.18603";
					VULN = TRUE;
				}
			}
		}
	}
	if(VULN){
		report = "File checked:     " + sysPath + "\\win32k.sys" + "\n" + "File version:     " + winVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
edgeVer = fetch_file_version( sysPath: sysPath, file_name: "Edgehtml.dll" );
if(!edgeVer){
	exit( 0 );
}
if(hotfix_check_sp( win10: 1, win10x64: 1, win2016: 1 ) > 0){
	if( version_is_less( version: edgeVer, test_version: "11.0.10240.17319" ) ){
		Vulnerable_range = "Less than 11.0.10240.17319";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: edgeVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.838" ) ){
			Vulnerable_range = "11.0.10586.0 - 11.0.10586.838";
			VULN = TRUE;
		}
		else {
			if(version_in_range( version: edgeVer, test_version: "11.0.14393.0", test_version2: "11.0.14393.952" )){
				Vulnerable_range = "11.0.14393.0 - 11.0.14393.952";
				VULN = TRUE;
			}
		}
	}
	if(VULN){
		report = "File checked:     " + sysPath + "\\Edgehtml.dll" + "\n" + "File version:     " + edgeVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

