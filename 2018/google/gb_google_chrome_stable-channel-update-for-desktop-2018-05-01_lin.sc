CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813370" );
	script_version( "2020-10-20T15:03:35+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-20 15:03:35 +0000 (Tue, 20 Oct 2020)" );
	script_tag( name: "creation_date", value: "2018-05-22 13:14:08 +0530 (Tue, 22 May 2018)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2018-05-01)-Linux" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to some unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to some unspecified
  security issues." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to have some unspecified impacts." );
	script_tag( name: "affected", value: "Google Chrome version prior to 66.0.3359.181
  on Linux." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 66.0.3359.181
  or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2018/05/stable-channel-update-for-desktop_15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_lin.sc" );
	script_mandatory_keys( "Google-Chrome/Linux/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
chr_ver = infos["version"];
chr_path = infos["location"];
if(version_is_less( version: chr_ver, test_version: "66.0.3359.181" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "66.0.3359.181", install_path: chr_path );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

