CPE = "cpe:/a:microsoft:ie";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807819" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-0187", "CVE-2016-0188", "CVE-2016-0189", "CVE-2016-0192", "CVE-2016-0194" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-05-11 10:25:55 +0530 (Wed, 11 May 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Internet Explorer Multiple Vulnerabilities (3155533)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-051." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Multiple memory corruption errors.

  - An error when Internet Explorer does not properly handle file access
    permissions.

  - An error in the User Mode Code Integrity (UMCI) component of Device Guard, when
    it improperly validates code integrity." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain access to potentially sensitive information, execute arbitrary
  code and bypass certain security restrictions on the affected system." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 9.x/10.x/11.x." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3155533" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-051" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_ms_ie_detect.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "MS/IE/Version" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("secpod_smb_func.inc.sc");
if(hotfix_check_sp( winVista: 3, win7: 2, win7x64: 2, win2008: 3, win2008r2: 2, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1, win10: 1, win10x64: 1 ) <= 0){
	exit( 0 );
}
iePath = smb_get_systemroot();
if(!iePath){
	exit( 0 );
}
iedllVer = fetch_file_version( sysPath: iePath, file_name: "system32\\Mshtml.dll" );
if(!iedllVer){
	exit( 0 );
}
if( hotfix_check_sp( winVista: 3, win2008: 3 ) > 0 ){
	if( version_in_range( version: iedllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16780" ) ){
		Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16780";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: iedllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20895" )){
			Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20895";
			VULN = TRUE;
		}
	}
}
else {
	if( hotfix_check_sp( win2012: 1 ) > 0 ){
		if(version_in_range( version: iedllVer, test_version: "10.0.9200.16000", test_version2: "10.0.9200.21840" )){
			Vulnerable_range = "10.0.9200.16000 - 10.0.9200.21840";
			VULN = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
			if(version_in_range( version: iedllVer, test_version: "11.0.9600.00000", test_version2: "11.0.9600.18320" )){
				Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18320";
				VULN = TRUE;
			}
		}
		else {
			if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2 ) > 0 ){
				if(version_in_range( version: iedllVer, test_version: "11.0.9600.00000", test_version2: "11.0.9600.18314" )){
					Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18314";
					VULN = TRUE;
				}
			}
			else {
				if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
					if( version_in_range( version: iedllVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.305" ) ){
						Vulnerable_range = "11.0.10586.0 - 11.0.10586.305";
						VULN = TRUE;
					}
					else {
						if(version_is_less( version: iedllVer, test_version: "11.0.10240.16847" )){
							Vulnerable_range = "Less than 11.0.10240.16847";
							VULN = TRUE;
						}
					}
				}
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + iePath + "\\system32\\Mshtml.dll" + "\n" + "File version:     " + iedllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

