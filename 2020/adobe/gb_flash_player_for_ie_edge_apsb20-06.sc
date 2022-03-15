if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815772" );
	script_version( "2021-10-05T11:36:17+0000" );
	script_cve_id( "CVE-2020-3757" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-10-06 10:22:49 +0000 (Wed, 06 Oct 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-26 21:15:00 +0000 (Thu, 26 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-02-12 10:55:18 +0530 (Wed, 12 Feb 2020)" );
	script_name( "Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (APSB20-06) - Windows" );
	script_tag( name: "summary", value: "Adobe Flash Player is prone to an arbitrary code execution vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to a type confusion issue." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers to
  execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Flash Player prior to 32.0.0.330
  within Microsoft Edge or Internet Explorer on,

  Windows 10 Version 1607 for x32/x64 Edition,

  Windows 10 Version 1709 for x32/x64 Edition,

  Windows 10 Version 1803 for x32/x64 Edition,

  Windows 10 Version 1809 for x32/x64 Edition,

  Windows 10 Version 1903 for x32/x64 Edition,

  Windows 10 Version 1909 for x32/x64 Edition,

  Windows 10 x32/x64 Edition,

  Windows 8.1 for x32/x64 Edition,

  Windows Server 2012/2012 R2,

  Windows Server 2016,

  Windows Server 2019" );
	script_tag( name: "solution", value: "Update to Adobe Flash Player 32.0.0.330 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb20-06.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "gb_flash_player_within_ie_edge_detect.sc" );
	script_mandatory_keys( "AdobeFlash/IE_or_EDGE/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
if(hotfix_check_sp( win8_1: 1, win8_1x64: 1, win2012: 1, win2012R2: 1, win10: 1, win10x64: 1, win2016: 1, win2019: 1 ) <= 0){
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
if(version_is_less( version: vers, test_version: "32.0.0.330" )){
	report = report_fixed_ver( file_checked: path, file_version: vers, vulnerable_range: "Less than 32.0.0.330" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

