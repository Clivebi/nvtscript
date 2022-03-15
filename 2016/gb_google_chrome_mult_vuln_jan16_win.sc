CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806929" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-8664", "CVE-2015-6792" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2016-01-05 13:05:38 +0530 (Tue, 05 Jan 2016)" );
	script_name( "Google Chrome Multiple Vulnerabilities Jan16 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An Integer overflow in the 'WebCursor::Deserialize' function in
    'content/common/cursors/webcursor.cc' script

  - An error in the MIDI subsystem does not properly handle the
    sending of data." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to execute arbitrary code or cause a denial of service or possibly have unspecified
  other impact." );
	script_tag( name: "affected", value: "Google Chrome versions prior to 47.0.2526.106
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  47.0.2526.106 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2015/12/stable-channel-update_15.html" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_google_chrome_detect_portable_win.sc" );
	script_mandatory_keys( "GoogleChrome/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!chromeVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: chromeVer, test_version: "47.0.2526.106" )){
	report = "Installed version: " + chromeVer + "\n" + "Fixed version:     47.0.2526.106" + "\n";
	security_message( data: report );
	exit( 0 );
}

