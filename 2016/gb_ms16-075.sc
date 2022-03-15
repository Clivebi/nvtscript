if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807340" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-3225" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:12:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-06-15 10:15:16 +0530 (Wed, 15 Jun 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Windows SMB Server Elevation of Privilege Vulnerability (3164038)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft Bulletin MS16-075." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An elevation of privilege flaw exists
  in the Microsoft Server Message Block (SMB) when an attacker forwards an
  authentication request intended for another service running on the same
  machine." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code with elevated permissions." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 x32/x64

  - Microsoft Windows Server 2012

  - Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012 R2

  - Microsoft Windows 7 x32/x64 Service Pack 1

  - Microsoft Windows Vista x32/x64 Service Pack 2

  - Microsoft Windows Server 2008 R2 x64 Service Pack 1

  - Microsoft Windows Server 2008 x32/x64 Service Pack 2" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-in/kb/3164038" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-075" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win8: 1, win8x64: 1, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
sysPath = smb_get_system32root();
if(!sysPath){
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "drivers\\mrxsmb10.sys" );
if(!sysVer){
	exit( 0 );
}
if( IsMatchRegexp( sysVer, "^6\\.0\\.6002\\.1" ) ){
	Vulnerable_range = "Less than 6.0.6002.19431";
}
else {
	if( IsMatchRegexp( sysVer, "^6\\.0\\.6002\\.2" ) ){
		Vulnerable_range = "6.0.6002.23000 - 6.0.6002.23973";
	}
	else {
		if( IsMatchRegexp( sysVer, "^6\\.1\\.7601\\.2" ) ){
			Vulnerable_range = "Less than 6.1.7601.23452";
		}
		else {
			if( IsMatchRegexp( sysVer, "^6\\.2\\.9200\\.2" ) ){
				Vulnerable_range = "Less than - 6.2.9200.21529";
			}
			else {
				if( IsMatchRegexp( sysVer, "^6\\.3\\.9600\\.1" ) ){
					Vulnerable_range = "Less than 6.3.9600.18298";
				}
				else {
					if( IsMatchRegexp( sysVer, "^10\\.0\\.10240" ) ){
						Vulnerable_range = "Less than 10.0.10240.16683";
					}
					else {
						if(IsMatchRegexp( sysVer, "^10\\.0\\.10586" )){
							Vulnerable_range = "10.0.10586.0 - 10.0.10586.102";
						}
					}
				}
			}
		}
	}
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	if(version_is_less( version: sysVer, test_version: "6.0.6002.19431" ) || version_in_range( version: sysVer, test_version: "6.0.6002.23000", test_version2: "6.0.6002.23973" )){
		VULN = TRUE;
	}
}
else {
	if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
		if(version_is_less( version: sysVer, test_version: "6.1.7601.23452" )){
			VULN = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( win2012: 1 ) > 0 ){
			if(version_is_less( version: sysVer, test_version: "6.2.9200.21529" )){
				VULN = TRUE;
			}
		}
		else {
			if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0){
				if(version_is_less( version: sysVer, test_version: "6.3.9600.18298" )){
					VULN = TRUE;
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\drivers\\mrxsmb10.sys" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}
sysVer = fetch_file_version( sysPath: sysPath, file_name: "edgehtml.dll" );
if(!sysVer){
	exit( 0 );
}
if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
	if( version_is_less( version: sysVer, test_version: "11.0.10240.16942" ) ){
		Vulnerable_range = "Less than 11.0.10240.16942";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: sysVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.419" )){
			Vulnerable_range = "11.0.10586.419";
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = "File checked:     " + sysPath + "\\edgehtml.dll" + "\n" + "File version:     " + sysVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

