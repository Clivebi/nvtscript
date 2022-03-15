CPE = "cpe:/a:microsoft:ie";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811561" );
	script_version( "2021-09-14T14:01:45+0000" );
	script_cve_id( "CVE-2017-8635", "CVE-2017-8636", "CVE-2017-8641", "CVE-2017-8651", "CVE-2017-8653", "CVE-2017-8669", "CVE-2017-0228" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-14 14:01:45 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-19 18:39:00 +0000 (Tue, 19 Mar 2019)" );
	script_tag( name: "creation_date", value: "2017-06-14 12:38:50 +0530 (Wed, 14 Jun 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Internet Explorer Multiple Vulnerabilities (KB4034733)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft security updates KB4034733." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - The way JavaScript engines render when handling objects in memory in
  Microsoft browsers.

  - The way that Microsoft browser JavaScript engines render content when handling
  objects in memory.

  - The way that JavaScript engines render when handling objects in memory in
  Microsoft browsers.

  - The way that Internet Explorer improperly accesses objects in memory.

  - The way that Microsoft browsers improperly access objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user, could gain the
  same user rights as the current user. If the current user is logged on with
  administrative user rights, an attacker who successfully exploited the
  vulnerability could take control of an affected system. An attacker could
  then install programs. View, change, or delete data, or create new accounts
  with full user rights." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 9.x, 10.x and 11.x." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4034733" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008: 3, win2008x64: 3, win7: 2, win7x64: 2, win2008r2: 2, win2012: 1, win2012R2: 1, win8_1: 1, win8_1x64: 1 ) <= 0){
	exit( 0 );
}
ieVer = get_app_version( cpe: CPE );
if(!ieVer || !IsMatchRegexp( ieVer, "^(9|1[01])\\." )){
	exit( 0 );
}
iePath = smb_get_system32root();
if(!iePath){
	exit( 0 );
}
iedllVer = fetch_file_version( sysPath: iePath, file_name: "Mshtml.dll" );
if(!iedllVer){
	exit( 0 );
}
if( hotfix_check_sp( win2008: 3, win2008x64: 3 ) > 0 ){
	if( version_in_range( version: iedllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16928" ) ){
		Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16928";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: iedllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.21039" )){
			Vulnerable_range = "9.0.8112.20000 - 9.0.8112.21039";
			VULN = TRUE;
		}
	}
}
else {
	if( hotfix_check_sp( win2012: 1 ) > 0 ){
		if(version_is_less( version: iedllVer, test_version: "10.0.9200.22227" )){
			Vulnerable_range = "Less than 10.0.9200.22227";
			VULN = TRUE;
		}
	}
	else {
		if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012R2: 1, win7: 2, win7x64: 2, win2008r2: 2 ) > 0){
			if(version_in_range( version: iedllVer, test_version: "11.0", test_version2: "11.0.9600.18762" )){
				Vulnerable_range = "11.0 - 11.0.9600.18762";
				VULN = TRUE;
			}
		}
	}
}
if(VULN){
	report = "File checked:     " + iePath + "\\Mshtml.dll" + "\n" + "File version:     " + iedllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
	security_message( data: report );
	exit( 0 );
}

