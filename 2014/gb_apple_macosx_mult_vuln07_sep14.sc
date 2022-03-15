if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804853" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1262", "CVE-2014-1255", "CVE-2014-1261", "CVE-2014-1263", "CVE-2014-1266", "CVE-2014-1264" );
	script_bugtraq_id( 65738, 65777 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-09-22 18:15:08 +0530 (Mon, 22 Sep 2014)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities -07 Sep14" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Two errors in the handling of Mach messages passed to ATS.

  - A signedness error in CoreText when handling certain Unicode fonts.

  - Two errors within the curl component.

  - A design error exists in Secure Transport.

  - An error in Finder when accessing ACLs." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to bypass security restrictions, capture or modify data, conduct denial of
  service and arbitrary code execution attacks." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.9.x before 10.9.2" );
	script_tag( name: "solution", value: "Run Mac Updates. Please see the references for more information." );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT6150" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT6150" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55446" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54960" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.9\\." );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer){
	exit( 0 );
}
if(ContainsString( osName, "Mac OS X" )){
	if(version_in_range( version: osVer, test_version: "10.9.0", test_version2: "10.9.1" )){
		report = report_fixed_ver( installed_version: osVer, vulnerable_range: "10.9.0 - 10.9.1" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

