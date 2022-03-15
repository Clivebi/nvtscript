CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804342" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1705", "CVE-2014-1713", "CVE-2014-1714", "CVE-2014-1715" );
	script_bugtraq_id( 66252, 66243, 66249, 66239 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-03-19 14:00:04 +0530 (Wed, 19 Mar 2014)" );
	script_name( "Google Chrome Multiple Vulnerabilities-03 Mar2014 (Windows)" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An unspecified error within V8.

  - A use-after-free error within 'AttributeSetter' function in the bindings in
  Blink.

  - Improper verification of certain format value by
  'ScopedClipboardWriter::WritePickledData' function.

  - Insufficient sanitization of user input by 'CreatePlatformFileUnsafe'
  function." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to conduct denial of
service, compromise a user's system and possibly unspecified other impacts." );
	script_tag( name: "affected", value: "Google Chrome version prior to 33.0.1750.154 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Google Chrome 33.0.1750.154 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/57439" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2014/03/stable-channel-update_14.html" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(version_is_less( version: chromeVer, test_version: "33.0.1750.154" )){
	report = report_fixed_ver( installed_version: chromeVer, fixed_version: "33.0.1750.154" );
	security_message( port: 0, data: report );
	exit( 0 );
}

