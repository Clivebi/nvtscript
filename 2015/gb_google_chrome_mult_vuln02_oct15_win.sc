CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805997" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2015-1304", "CVE-2015-1303" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-10-19 13:25:32 +0530 (Mon, 19 Oct 2015)" );
	script_name( "Google Chrome Multiple Vulnerabilities-02 Oct15 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in 'object-observe.js' script in Google V8 which does not
    properly restrict method calls on access-checked objects.

  - An error in bindings/core/v8/V8DOMWrapper.h script in Blink which does not
    perform a rethrow action to propagate information about a cross-context
    exception." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker
  to bypass certain security restrictions." );
	script_tag( name: "affected", value: "Google Chrome versions prior to 45.0.2454.101
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  45.0.2454.101 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2015/09/stable-channel-update_24.html" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
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
if(version_is_less( version: chromeVer, test_version: "45.0.2454.101" )){
	report = "Installed version: " + chromeVer + "\n" + "Fixed version:     45.0.2454.101" + "\n";
	security_message( data: report );
	exit( 0 );
}

