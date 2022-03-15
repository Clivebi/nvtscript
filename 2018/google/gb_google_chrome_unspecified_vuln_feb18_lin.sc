CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812803" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_cve_id( "CVE-2018-6056" );
	script_bugtraq_id( 103003 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-29 19:41:00 +0000 (Tue, 29 Jan 2019)" );
	script_tag( name: "creation_date", value: "2018-02-16 17:51:54 +0530 (Fri, 16 Feb 2018)" );
	script_name( "Google Chrome Unspecified Security Vulnerability Feb18 (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Google Chrome
  and is prone to an unspecified remote security vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an incorrect derived
  class instantiation in V8." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  will allow remote attackers to have an unknown impact on affected system." );
	script_tag( name: "affected", value: "Google Chrome version prior to 64.0.3282.167
  on Linux." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 64.0.3282.167
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2018/02/stable-channel-update-for-desktop_13.html" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "64.0.3282.167" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "64.0.3282.167", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

