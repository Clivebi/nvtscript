if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814983" );
	script_version( "2021-08-30T14:01:20+0000" );
	script_cve_id( "CVE-2019-7845" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-30 14:01:20 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-17 11:16:00 +0000 (Mon, 17 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-06-12 11:57:03 +0530 (Wed, 12 Jun 2019)" );
	script_name( "Adobe Flash Player Microsoft Edge and Internet Explorer Security Update (apsb19-30) - Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  within Microsoft Edge or Internet Explorer and is prone to an use after free
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an use after free
  error." );
	script_tag( name: "impact", value: "Successful exploitation allows attackers
  to conduct arbitrary code execution in the context of current user." );
	script_tag( name: "affected", value: "Adobe Flash Player prior to 32.0.0.207
  within Microsoft Edge or Internet Explorer on,

  Windows 10 Version 1607 for x32/x64 Edition,

  Windows 10 Version 1703 for x32/x64 Edition,

  Windows 10 Version 1709 for x32/x64 Edition,

  Windows 10 Version 1803 for x32/x64 Edition,

  Windows 10 Version 1809 for x32/x64 Edition,

  Windows 10 x32/x64 Edition,

  Windows 8.1 for x32/x64 Edition,

  Windows Server 2012/2012 R2,

  Windows Server 2016,

  Windows Server 2019" );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player 32.0.0.207 or later.
  Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb19-30.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
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
	path = path + "\\Flashplayerapp.exe";
}
else {
	path = "Could not find the install location";
}
if(version_is_less( version: vers, test_version: "32.0.0.207" )){
	report = report_fixed_ver( file_checked: path, file_version: vers, vulnerable_range: "Less than 32.0.0.207" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );
