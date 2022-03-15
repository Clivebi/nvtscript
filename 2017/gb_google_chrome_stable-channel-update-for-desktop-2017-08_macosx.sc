CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811641" );
	script_version( "2019-07-17T08:15:16+0000" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-17 08:15:16 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2017-08-29 11:54:39 +0530 (Tue, 29 Aug 2017)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-for-desktop-2017-08)-Mac OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to an unknown vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists due to an unknown error." );
	script_tag( name: "impact", value: "Successful exploitation of these
  vulnerabilities will allow remote attacker to bypass security, execute
  arbitrary code, cause denial of service and conduct spoofing attacks." );
	script_tag( name: "affected", value: "Google Chrome version prior to 60.0.3112.113 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 60.0.3112.113 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "https://chromereleases.googleblog.com/2017/08/stable-channel-update-for-desktop.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chr_ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chr_ver, test_version: "60.0.3112.113" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "60.0.3112.113" );
	security_message( data: report );
	exit( 0 );
}

