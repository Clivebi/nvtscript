CPE = "cpe:/a:mozilla:firefox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805248" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-8643", "CVE-2014-8642", "CVE-2014-8641", "CVE-2014-8640", "CVE-2014-8639", "CVE-2014-8638", "CVE-2014-8637", "CVE-2014-8636", "CVE-2014-8635", "CVE-2014-8634" );
	script_bugtraq_id( 72043, 72042, 72044, 72045, 72046, 72047, 72048, 72041, 72050, 72049 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-01-20 12:51:45 +0530 (Tue, 20 Jan 2015)" );
	script_name( "Mozilla Firefox Multiple Vulnerabilities-01 Jan15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Some unspecified errors.

  - An error when rendering a bitmap image by the bitmap decoder within a
  canvas element.

  - An error when handling a request from 'navigator.sendBeacon' API interface
  function.

  - An error when handling a '407 Proxy Authentication' response with a
  'Set-Cookie' header from a web proxy.

  - A use-after-free error when handling tracks within WebRTC.

  - An unspecified error related to the GMP (Gecko Media Plugin) sandbox.

  - An error when handling the 'id-pkix-ocsp-nocheck' extension during
  verification of a delegated OCSP (Online Certificate Status Protocol) response
  signing certificate.

  - An error when handling DOM (Document Object Model) objects with certain
  properties.

  - Improper restriction of timeline operations by the
  'mozilla::dom::AudioParamTimeline::AudioNodeInputValue' function in the Web
  Audio API." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to disclose potentially sensitive information, bypass certain security
  restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "Mozilla Firefox before version 35.0 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox version 35.0
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62253" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-01" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-03" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-04" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-02" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-05" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-09" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-08" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-07" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-06" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!ffVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ffVer, test_version: "35.0" )){
	fix = "35.0";
	report = "Installed version: " + ffVer + "\n" + "Fixed version:     " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

