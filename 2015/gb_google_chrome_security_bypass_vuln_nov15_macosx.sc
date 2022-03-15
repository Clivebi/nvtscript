CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806569" );
	script_version( "2019-07-17T08:15:16+0000" );
	script_cve_id( "CVE-2015-1302" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-07-17 08:15:16 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-11-13 18:16:04 +0530 (Fri, 13 Nov 2015)" );
	script_name( "Google Chrome PDF Viewer Security Bypass Vulnerability Nov15 (Mac OS X)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to PDF viewer which does
  not properly restrict scripting messages and API exposure." );
	script_tag( name: "impact", value: "Successful exploitation would allow remote
  attackers to bypass the Same Origin Policy." );
	script_tag( name: "affected", value: "Google Chrome versions prior to
  46.0.2490.86 on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  46.0.2490.86 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2015/11/stable-channel-update.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_macosx.sc" );
	script_mandatory_keys( "GoogleChrome/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "46.0.2490.86" )){
	report = "Installed version: " + chromeVer + "\n" + "Fixed version:     46.0.2490.86" + "\n";
	security_message( data: report );
	exit( 0 );
}

