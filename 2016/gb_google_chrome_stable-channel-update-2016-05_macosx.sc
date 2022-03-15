CPE = "cpe:/a:google:chrome";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807591" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2016-1667", "CVE-2016-1668", "CVE-2016-1669", "CVE-2016-1670" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "creation_date", value: "2016-05-17 11:47:13 +0530 (Tue, 17 May 2016)" );
	script_name( "Google Chrome Security Updates(stable-channel-update-2016-05)-MAC OS X" );
	script_tag( name: "summary", value: "The host is installed with Google Chrome
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Same origin bypass in DOM.

  - Same origin bypass in Blink V8 bindings.

  - Buffer overflow in V8.

  - Race condition in loader." );
	script_tag( name: "impact", value: "Successful exploitation of this
  vulnerability will allow remote attackers to bypass security restrictions,
  to obtain sensitive information and to cause a denial of service
  (buffer overflow) or possibly have unspecified other impact." );
	script_tag( name: "affected", value: "Google Chrome version
  prior to 50.0.2661.102 on MAC OS X" );
	script_tag( name: "solution", value: "Upgrade to Google Chrome version
  50.0.2661.102 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_xref( name: "URL", value: "http://googlechromereleases.blogspot.in/2016/05/stable-channel-update.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
if(version_is_less( version: chr_ver, test_version: "50.0.2661.102" )){
	report = report_fixed_ver( installed_version: chr_ver, fixed_version: "50.0.2661.102" );
	security_message( data: report );
	exit( 0 );
}

