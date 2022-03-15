if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902715" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2010-4013" );
	script_bugtraq_id( 45693 );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-23 07:05:00 +0200 (Tue, 23 Aug 2011)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Apple Mac OS X PackageKit Format String Vulnerability" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.6\\." );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4498" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/42841" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id?1024938" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce//2011//Jan/msg00000.html" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause an unexpected
  application termination or arbitrary code execution." );
	script_tag( name: "affected", value: "Mac OS X version 10.6 through 10.6.5

  Mac OS X Server version 10.6 through 10.6.5." );
	script_tag( name: "insight", value: "The flaw is due to a format string error in PackageKit's handling of
  distribution scripts. A man-in-the-middle attacker may be able to cause an unexpected application termination
  or arbitrary code execution when the Software Update checks for new updates." );
	script_tag( name: "solution", value: "Upgrade to Mac OS X/Server version 10.6.6 or later." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Mac OS X 10.6.6 Update." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName || !ContainsString( osName, "Mac OS X" )){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer){
	exit( 0 );
}
if(IsMatchRegexp( osVer, "^10\\.6\\." ) && version_in_range( version: osVer, test_version: "10.6.0", test_version2: "10.6.5" )){
	report = report_fixed_ver( installed_version: osVer, fixed_version: "10.6.6" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

