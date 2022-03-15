CPE = "cpe:/a:adobe:flash_player_chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810657" );
	script_version( "2021-09-16T08:01:42+0000" );
	script_cve_id( "CVE-2016-1096", "CVE-2016-1097", "CVE-2016-1098", "CVE-2016-1099", "CVE-2016-1100", "CVE-2016-1101", "CVE-2016-1102", "CVE-2016-1103", "CVE-2016-1104", "CVE-2016-1105", "CVE-2016-1106", "CVE-2016-1107", "CVE-2016-1108", "CVE-2016-1109", "CVE-2016-1110", "CVE-2016-4108", "CVE-2016-4109", "CVE-2016-4110", "CVE-2016-4111", "CVE-2016-4112", "CVE-2016-4113", "CVE-2016-4114", "CVE-2016-4115", "CVE-2016-4116", "CVE-2016-4117", "CVE-2016-4120", "CVE-2016-4121", "CVE-2016-4160", "CVE-2016-4161", "CVE-2016-4162", "CVE-2016-4163" );
	script_bugtraq_id( 90620, 90621, 90505, 90619, 90618, 90617, 90616 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-16 08:01:42 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-02-12 11:29:00 +0000 (Tue, 12 Feb 2019)" );
	script_tag( name: "creation_date", value: "2017-03-18 15:02:18 +0530 (Sat, 18 Mar 2017)" );
	script_name( "Adobe Flash Player Within Google Chrome Security Update (apsb16-15) - Linux" );
	script_tag( name: "summary", value: "This host is installed with Adobe Flash Player
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to:

  - Multiple type confusion vulnerabilities.

  - Multiple use-after-free vulnerabilities.

  - A heap buffer overflow vulnerability.

  - A buffer overflow vulnerability.

  - Multiple memory corruption vulnerabilities.

  - A vulnerability in the directory search path used to find resources." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attackers to execute arbitrary code and
  also some unknown impact." );
	script_tag( name: "affected", value: "Adobe Flash Player for chrome versions
  before 21.0.0.242 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Flash Player for chrome
  version 21.0.0.242 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/flash-player/apsb16-15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_flash_player_within_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "AdobeFlashPlayer/Chrome/Lin/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!playerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: playerVer, test_version: "21.0.0.242" )){
	report = report_fixed_ver( installed_version: playerVer, fixed_version: "21.0.0.242" );
	security_message( data: report );
	exit( 0 );
}

