CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804927" );
	script_version( "2020-04-20T13:31:49+0000" );
	script_cve_id( "CVE-2014-1568" );
	script_bugtraq_id( 70116 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-20 13:31:49 +0000 (Mon, 20 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-09-30 10:00:31 +0530 (Tue, 30 Sep 2014)" );
	script_name( "Google Chrome RSA Spoof Vulnerability September14 (Macosx)" );
	script_tag( name: "summary", value: "This host is installed with Google Chrome
  and is prone to spoof vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw exists due to improper handling of
  ASN.1 values while parsing RSA signature" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to conduct spoofing attacks." );
	script_tag( name: "affected", value: "Google Chrome before 37.0.2062.124 on Macosx" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version 37.0.2062.124
  or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2014/09/stable-channel-update-for-chrome-os_24.html" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2014/09/stable-channel-update_24.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(version_is_less( version: chromeVer, test_version: "37.0.2062.124" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "37.0.2062.124" );
	security_message( port: 0, data: report );
	exit( 0 );
}

