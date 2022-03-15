CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805253" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-8639", "CVE-2014-8638", "CVE-2014-8634" );
	script_bugtraq_id( 72046, 72047, 72049 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-01-20 14:31:54 +0530 (Tue, 20 Jan 2015)" );
	script_name( "Mozilla Thunderbird Multiple Vulnerabilities-01 Jan15 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error when handling a '407 Proxy Authentication' response with a
  'Set-Cookie' header from a web proxy.

  - Some unspecified errors.

  - An error when handling a request from 'navigator.sendBeacon' API interface
  function." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions, and compromise a user's
  system." );
	script_tag( name: "affected", value: "Mozilla Thunderbird before version 31.4
  on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version
  31.4 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62253" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-04" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-03" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-01" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "executable_version" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_mozilla_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Thunderbird/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "31.4" )){
	fix = "31.4";
	report = "Installed version: " + vers + "\n" + "Fixed version:     " + fix + "\n";
	security_message( data: report );
	exit( 0 );
}

