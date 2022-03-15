CPE = "cpe:/a:microsoft:ie";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813023" );
	script_version( "2021-06-23T02:00:29+0000" );
	script_cve_id( "CVE-2018-0889", "CVE-2018-0891", "CVE-2018-0929", "CVE-2018-0935" );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-06-23 02:00:29 +0000 (Wed, 23 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-03-14 11:36:36 +0530 (Wed, 14 Mar 2018)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Microsoft Internet Explorer Memory Corruption And Information Disclosure Vulnerabilities (KB4089187)" );
	script_tag( name: "summary", value: "This host is missing an important security
  update according to Microsoft security updates KB4089187." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist when Internet Explorer
  improperly handles objects in memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker
  to obtain information to further compromise the user's system and execute
  arbitrary code in the context of the current user." );
	script_tag( name: "affected", value: "Microsoft Internet Explorer version 9.x." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://support.microsoft.com/en-us/help/4089187" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
if(hotfix_check_sp( win2008: 3, win2008x64: 3 ) <= 0){
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
if(version_in_range( version: iedllVer, test_version: "9.0.8112.20000", test_version2: "9.0.8112.21107" )){
	report = report_fixed_ver( file_checked: iePath + "\\Mshtml.dll", file_version: iedllVer, vulnerable_range: "9.0.8112.20000 - 9.0.8112.21107" );
	security_message( data: report );
}
exit( 0 );

