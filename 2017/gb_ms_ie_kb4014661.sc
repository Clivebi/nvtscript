CPE = "cpe:/a:microsoft:ie";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810853" );
	script_version( "2021-09-13T13:01:42+0000" );
	script_cve_id( "CVE-2017-0201" );
	script_bugtraq_id( 97454 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-13 13:01:42 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-03-15 12:07:36 +0530 (Wed, 15 Mar 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Internet Explorer Remote Code Execution Vulnerability (KB4014661)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft security updates KB4014661." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in the way that the JScript
  and VBScript engines render when handling objects in memory in Internet Explorer." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to execute arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 9.x." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4014661" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4014661/cumulative-security-update-for-internet-explorer-april-11-2017" );
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
if(hotfix_check_sp( winVista: 3, winVistax64: 3, win2008: 3, win2008x64: 3 ) <= 0){
	exit( 0 );
}
ieVer = get_app_version( cpe: CPE );
if(!ieVer || !IsMatchRegexp( ieVer, "^9\\." )){
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
if(hotfix_check_sp( winVista: 3, win2008: 3, winVistax64: 3, win2008x64: 3 ) > 0){
	if( version_in_range( version: iedllVer, test_version: "9.0.8112.16000", test_version2: "9.0.8112.16871" ) ){
		Vulnerable_range = "9.0.8112.16000 - 9.0.8112.16871";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: iedllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.20985" )){
			Vulnerable_range = "9.0.8112.20000 - 9.0.8112.20985";
			VULN = TRUE;
		}
	}
	if(VULN){
		report = "File checked:     " + iePath + "\\Mshtml.dll" + "\n" + "File version:     " + iedllVer + "\n" + "Vulnerable range: " + Vulnerable_range + "\n";
		security_message( data: report );
		exit( 0 );
	}
}
exit( 0 );

