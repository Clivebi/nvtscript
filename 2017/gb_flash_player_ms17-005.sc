if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810610" );
	script_version( "2021-09-10T13:01:42+0000" );
	script_cve_id( "CVE-2017-2982", "CVE-2017-2984", "CVE-2017-2985", "CVE-2017-2986", "CVE-2017-2987", "CVE-2017-2988", "CVE-2017-2990", "CVE-2017-2991", "CVE-2017-2992", "CVE-2017-2993", "CVE-2017-2994", "CVE-2017-2995", "CVE-2017-2996" );
	script_bugtraq_id( 96199, 96193, 96194, 96190, 96191, 96190 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 13:01:42 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-03-09 17:21:29 +0530 (Thu, 09 Mar 2017)" );
	script_name( "Microsoft IE And Microsoft Edge Multiple Flash Player Vulnerabilities (4010250)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft Bulletin MS17-005." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A type confusion vulnerability.

  - Multiple use-after-free vulnerabilities.

  - An integer overflow vulnerability.

  - Multiple heap buffer overflow vulnerabilities.

  - Multiple memory corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code on
  the target user's system and that could potentially allow an attacker to
  take control of the affected system." );
	script_tag( name: "affected", value: "- Microsoft Windows 8.1 x32/x64

  - Microsoft Windows Server 2012/2012R2

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 10 Version 1511 x32/x64

  - Microsoft Windows 10 Version 1607 x32/x64

  - Microsoft Windows Server 2016 x64" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://technet.microsoft.com/library/security/ms17-005" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb17-04.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_flash_player_within_ie_edge_detect.sc" );
	script_mandatory_keys( "AdobeFlash/IE_or_EDGE/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1, win2016: 1 ) <= 0){
	exit( 0 );
}
cpe_list = make_list( "cpe:/a:adobe:flash_player_internet_explorer",
	 "cpe:/a:adobe:flash_player_edge" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if( path ){
	path += "\\Flashplayerapp.exe";
}
else {
	path = "Could not find the install location";
}
if(version_is_less( version: vers, test_version: "24.0.0.221" )){
	report = report_fixed_ver( file_checked: path, file_version: vers, vulnerable_range: "Less than 24.0.0.221" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

