CPE = "cpe:/a:mozilla:firefox_esr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804090" );
	script_version( "2020-12-16T12:38:30+0000" );
	script_cve_id( "CVE-2014-1477", "CVE-2014-1479", "CVE-2014-1481", "CVE-2014-1482", "CVE-2014-1486", "CVE-2014-1487", "CVE-2014-1490", "CVE-2014-1491" );
	script_bugtraq_id( 65317, 65320, 65326, 65328, 65334, 65330, 65335, 65332 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-12-16 12:38:30 +0000 (Wed, 16 Dec 2020)" );
	script_tag( name: "creation_date", value: "2014-02-11 19:12:08 +0530 (Tue, 11 Feb 2014)" );
	script_name( "Mozilla Firefox ESR Multiple Vulnerabilities-01 Feb14 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Mozilla Firefox and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - An error when handling XML Binding Language (XBL) content scopes

  - An error when handling discarded images within the 'RasterImage' class

  - A use-after-free error related to certain content types when used with the
  'imgRequestProxy()' function

  - An error when handling web workers error messages

  - A race condition error when handling session tickets within libssl

  - An error when handling JavaScript native getters on window objects" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions and compromise a user's system." );
	script_tag( name: "affected", value: "Mozilla Firefox ESR version 24.x before 24.3 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Mozilla Firefox ESR version 24.3 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/56767" );
	script_xref( name: "URL", value: "http://www.mozilla.org/security/announce/2014/mfsa2014-01.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_firefox_detect_portable_win.sc" );
	script_mandatory_keys( "Firefox-ESR/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^24\\." ) && version_in_range( version: vers, test_version: "24.0", test_version2: "24.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "24.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

