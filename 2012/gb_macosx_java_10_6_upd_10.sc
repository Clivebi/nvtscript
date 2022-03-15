if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803029" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_bugtraq_id( 55339 );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-09-21 11:04:53 +0530 (Fri, 21 Sep 2012)" );
	script_name( "Java for Mac OS X 10.6 Update 10" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.6\\.8" );
	script_xref( name: "URL", value: "https://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2012-0547" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5473" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50133" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027458" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2012/Sep/msg00000.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html" );
	script_tag( name: "impact", value: "Has no impact and remote attack vectors. The missing patch is a security-in-depth fix released by Oracle." );
	script_tag( name: "affected", value: "Java for Mac OS X v10.6.8 or Mac OS X Server v10.6.8" );
	script_tag( name: "insight", value: "Unspecified vulnerability in the JRE component related to AWT sub-component." );
	script_tag( name: "solution", value: "Upgrade to Java for Mac OS X 10.6 Update 10." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Java for Mac OS X 10.6 Update 10." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("pkg-lib-macosx.inc.sc");
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
	if(version_is_equal( version: osVer, test_version: "10.6.8" )){
		if(isosxpkgvuln( fixed: "com.apple.pkg.JavaForMacOSX10.6", diff: "10" )){
			report = report_fixed_ver( installed_version: osVer, vulnerable_range: "Equal to 10.6.8" );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

