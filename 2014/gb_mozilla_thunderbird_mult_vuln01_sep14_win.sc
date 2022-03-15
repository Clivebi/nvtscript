CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804833" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1562", "CVE-2014-1567" );
	script_bugtraq_id( 69519, 69520 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-09-05 19:57:31 +0530 (Fri, 05 Sep 2014)" );
	script_name( "Mozilla Thunderbird Multiple Vulnerabilities-01 September14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla
  Thunderbird and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A use-after-free error when setting text directionality.

  - An unspecified error." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to disclose potentially sensitive information and compromise a user's system." );
	script_tag( name: "affected", value: "Mozilla Thunderbird 24.x before 24.8 and
  31.x before 31.1 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 24.8
  or 31.1 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-67.html" );
	script_xref( name: "URL", value: "https://www.mozilla.org/security/announce/2014/mfsa2014-72.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_thunderbird_detect_portable_win.sc" );
	script_mandatory_keys( "Thunderbird/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!vers = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( vers, "^(24|31)\\." )){
	if(( version_in_range( version: vers, test_version: "24.0", test_version2: "24.7" ) ) || ( version_is_equal( version: vers, test_version: "31.0" ) )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

