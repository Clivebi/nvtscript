if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811193" );
	script_version( "2021-09-10T11:01:38+0000" );
	script_cve_id( "CVE-2017-3075", "CVE-2017-3081", "CVE-2017-3083", "CVE-2017-3084", "CVE-2017-3076", "CVE-2017-3077", "CVE-2017-3078", "CVE-2017-3079", "CVE-2017-3082" );
	script_bugtraq_id( 99023, 99025 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 11:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:31:00 +0000 (Fri, 05 Jan 2018)" );
	script_tag( name: "creation_date", value: "2017-06-14 08:23:18 +0530 (Wed, 14 Jun 2017)" );
	script_name( "Microsoft IE And Microsoft Edge Multiple Flash Player Vulnerabilities (4022730)" );
	script_tag( name: "summary", value: "This host is missing a critical security
  update according to Microsoft KB4022730." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A use-after-free vulnerability and

  - The memory corruption vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to perform code execution." );
	script_tag( name: "affected", value: "- Microsoft Windows 10 Version 1511 for x32/x64

  - Microsoft Windows 10 Version 1607 for x32/x64

  - Microsoft Windows 10 Version 1703 for x32/x64

  - Microsoft Windows 10 x32/x64

  - Microsoft Windows 8.1 for x32/x64 Edition and

  - Microsoft Windows Server 2012/2012 R2/2016" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://support.microsoft.com/kb/4022730" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb17-17.html" );
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
if(version_is_less( version: vers, test_version: "26.0.0.126" )){
	report = report_fixed_ver( file_checked: path, file_version: vers, vulnerable_range: "Less than 26.0.0.126" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

