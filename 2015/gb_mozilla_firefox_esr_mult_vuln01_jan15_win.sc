CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805250" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-8641", "CVE-2014-8639", "CVE-2014-8638", "CVE-2014-8634" );
	script_bugtraq_id( 72044, 72046, 72047, 72049 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-01-20 13:51:45 +0530 (Tue, 20 Jan 2015)" );
	script_name( "Mozilla Firefox ESR Multiple Vulnerabilities-01 Jan15 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox ESR
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A use-after-free error when handling tracks within WebRTC.

  - An error when handling a '407 Proxy Authentication' response with a
  'Set-Cookie' header from a web proxy.

  - Some unspecified errors.

  - An error when handling a request from 'navigator.sendBeacon' API interface
  function." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to bypass certain security restrictions, and compromise a user's
  system." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR 31.x before 31.4 on
  Windows" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 31.4
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "registry" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/62253" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-06" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-04" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-03" );
	script_xref( name: "URL", value: "https://www.mozilla.org/en-US/security/advisories/mfsa2015-01" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^31\\." )){
	if(( version_in_range( version: vers, test_version: "31.0", test_version2: "31.3" ) )){
		fix = "31.4";
		report = "Installed version: " + vers + "\n" + "Fixed version:     " + fix + "\n";
		security_message( data: report );
		exit( 0 );
	}
}

