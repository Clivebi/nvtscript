CPE = "cpe:/a:apple:safari";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804750" );
	script_version( "$Revision: 14318 $" );
	script_cve_id( "CVE-2014-1382", "CVE-2014-1325", "CVE-2014-1340", "CVE-2014-1345", "CVE-2014-1362", "CVE-2014-1363", "CVE-2014-1364", "CVE-2014-1365", "CVE-2014-1366", "CVE-2014-1367", "CVE-2014-1368", "CVE-2014-1369" );
	script_bugtraq_id( 68271, 68271, 68275, 68276, 68271, 68271, 68271, 68271, 68271, 68271, 68271, 68329 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-19 12:44:05 +0100 (Tue, 19 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2014-08-25 21:22:02 +0530 (Mon, 25 Aug 2014)" );
	script_name( "Apple Safari Multiple Memory Corruption Vulnerabilities-01 Aug14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Apple Safari and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaws are due to muliple unspecified errors in the WebKit" );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to bypass a sandbox protection
  mechanism, execute arbitrary code with root privileges via unknown vectors and corrupt memory." );
	script_tag( name: "affected", value: "Apple Safari version before 6.1.5 and 7.x before 7.0.5 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Apple Safari version 6.1.5 or 7.0.5 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT6293" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/59481" );
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
if(version_in_range( version: safVer, test_version: "6.0", test_version2: "6.1.4" ) || version_in_range( version: safVer, test_version: "7.0", test_version2: "7.0.4" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
	exit( 0 );
}

