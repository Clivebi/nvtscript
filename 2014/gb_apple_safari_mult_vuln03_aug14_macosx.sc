CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804752" );
	script_version( "$Revision: 14318 $" );
	script_cve_id( "CVE-2014-1323", "CVE-2014-1324", "CVE-2014-1326", "CVE-2014-1327", "CVE-2014-1329", "CVE-2014-1330", "CVE-2014-1331", "CVE-2014-1333", "CVE-2014-1334", "CVE-2014-1335", "CVE-2014-1336", "CVE-2014-1337", "CVE-2014-1338", "CVE-2014-1339", "CVE-2014-1341", "CVE-2014-1342", "CVE-2014-1343", "CVE-2014-1344", "CVE-2014-1346" );
	script_bugtraq_id( 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67553, 67554 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 12:44:05 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-25 21:42:57 +0530 (Mon, 25 Aug 2014)" );
	script_name( "Apple Safari Multiple Memory Corruption Vulnerabilities-03 Aug14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Apple Safari and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to muliple unspecified errors in the WebKit and an error exists
  when handling unicode characters in URLs in WebKit" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass certain security
  restrictions and compromise a user's system." );
	script_tag( name: "affected", value: "Apple Safari version before 6.1.4 and 7.x before 7.0.4 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 6.1.4 or 7.0.4 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT6254" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/58890" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "macosx_safari_detect.sc" );
	script_mandatory_keys( "AppleSafari/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!safVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: safVer, test_version: "6.0", test_version2: "6.1.3" ) || version_in_range( version: safVer, test_version: "7.0", test_version2: "7.0.3" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

