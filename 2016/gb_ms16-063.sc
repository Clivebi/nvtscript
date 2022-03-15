CPE = "cpe:/a:microsoft:ie";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807837" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_cve_id( "CVE-2016-0199", "CVE-2016-0200", "CVE-2016-3202", "CVE-2016-3205", "CVE-2016-3206", "CVE-2016-3207", "CVE-2016-3210", "CVE-2016-3211", "CVE-2016-3212", "CVE-2016-3213" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-12 22:11:00 +0000 (Fri, 12 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-06-15 08:02:15 +0530 (Wed, 15 Jun 2016)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Internet Explorer Multiple Vulnerabilities (3163649)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS16-063." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error when Internet Explorer improperly accesses objects in memory.

  - An error in the way that the JScript 9, JScript, and VBScript engines render
  when handling objects in memory.

  - Internet Explorer XSS Filter does not properly validate JavaScript under
  specific conditions.

  - An error when the Web Proxy Auto Discovery (WPAD) protocol falls back to a
  vulnerable proxy discovery process." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass security, gain elevated privileges and execute arbitrary code
  on the affected system." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 9.x/10.x/11.x." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/kb/3163649" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/MS16-063" );
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
	if( version_in_range( version: iedllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16788" ) ){
		Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16788";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: iedllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20903" )){
			Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20903";
			VULN = TRUE;
		}
	}
}
else {
	if( hotfix_check_sp( win2012: 1 ) > 0 ){
		if(version_in_range( version: iedllVer, test_version: "10.0.9200.16000", test_version2: "10.0.9200.21859" )){
			Vulnerable_range = "10.0.9200.16000 - 10.0.9200.21859";
			VULN = TRUE;
		}
	}
	else {
		if( hotfix_check_sp( win7: 2, win7x64: 2, win2008r2: 2, win8_1: 1, win8_1x64: 1, win2012R2: 1 ) > 0 ){
			if(version_in_range( version: iedllVer, test_version: "11.0.9600.00000", test_version2: "11.0.9600.18348" )){
				Vulnerable_range = "11.0.9600.00000 - 11.0.9600.18348";
				VULN = TRUE;
			}
		}
		else {
			if(hotfix_check_sp( win10: 1, win10x64: 1 ) > 0){
				if( version_in_range( version: iedllVer, test_version: "11.0.10586.0", test_version2: "11.0.10586.419" ) ){
					Vulnerable_range = "11.0.10586.0 - 11.0.10586.419";
					VULN = TRUE;
				}
				else {
					if(version_is_less( version: iedllVer, test_version: "11.0.10240.16942" )){
						Vulnerable_range = "Less than 11.0.10240.16942";
						VULN = TRUE;
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

