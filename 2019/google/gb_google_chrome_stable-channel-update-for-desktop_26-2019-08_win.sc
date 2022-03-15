CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.815444" );
	script_version( "2021-09-08T09:01:34+0000" );
	script_cve_id( "CVE-2019-5869" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-08 09:01:34 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2019-08-27 17:12:19 +0530 (Tue, 27 Aug 2019)" );
	script_name( "Google Chrome Security Update(stable-channel-update-for-desktop_26-2019-08)-Windows" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to an use after free vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an use-after-free error
  in Blink." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to perform an out of bounds memory read or execute arbitrary code
  via a crafted HTML page" );
	script_tag( name: "affected", value: "Google Chrome version prior to 76.0.3809.132 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  76.0.3809.132 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2019/08/stable-channel-update-for-desktop_26.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "76.0.3809.132" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "76.0.3809.132", install_path: path );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

