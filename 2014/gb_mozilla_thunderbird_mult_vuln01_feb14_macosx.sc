CPE = "cpe:/a:mozilla:thunderbird";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804093" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1490", "CVE-2014-1491" );
	script_bugtraq_id( 65317, 65320, 65326, 65328, 65334, 65330, 65335, 65332 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-02-11 19:36:46 +0530 (Tue, 11 Feb 2014)" );
	script_name( "Mozilla Thunderbird Multiple Vulnerabilities-01 Feb14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Thunderbird and is prone to multiple
vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error when handling XML Binding Language (XBL) content scopes.

  - An error when handling discarded images within the 'RasterImage' class.

  - A use-after-free error related to certain content types when used with the
  'imgRequestProxy()' function.

  - An error when handling web workers error messages.

  - A race condition error when handling session tickets within libssl.

  - An error when handling JavaScript native getters on window objects." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
restrictions and compromise a user's system." );
	script_tag( name: "affected", value: "Mozilla Thunderbird version before 24.3 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Mozilla Thunderbird version 24.3 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56767" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-01.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
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
if(version_is_less( version: vers, test_version: "24.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "24.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}

