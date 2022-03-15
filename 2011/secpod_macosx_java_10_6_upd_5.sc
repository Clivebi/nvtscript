if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902554" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-26 14:59:42 +0200 (Fri, 26 Aug 2011)" );
	script_cve_id( "CVE-2011-0802", "CVE-2011-0814", "CVE-2011-0862", "CVE-2011-0863", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0867", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0871", "CVE-2011-0873" );
	script_bugtraq_id( 48137, 48138, 48140, 48144, 48145, 48147, 48148, 48149 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Java for Mac OS X 10.6 Update 5" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4738" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce//2011//Jun/msg00001.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.6\\.[6-8]" );
	script_tag( name: "impact", value: "Successful exploitation may allow an untrusted Java applet to execute
  arbitrary code outside the Java sandbox. Visiting a web page containing
  a maliciously crafted untrusted Java applet may lead to arbitrary code
  execution with the privileges of the current user." );
	script_tag( name: "affected", value: "Java for Mac OS X v10.6.6 and later or Mac OS X Server v10.6.6 and later." );
	script_tag( name: "insight", value: "For more information on the vulnerabilities refer the below links." );
	script_tag( name: "solution", value: "Upgrade to Java for Mac OS X 10.6 Update 5." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Java for Mac OS X 10.6 Update 5." );
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
if(ContainsString( osName, "Mac OS X" ) || ContainsString( osName, "Mac OS X Server" )){
	if(version_in_range( version: osVer, test_version: "10.6.6", test_version2: "10.6.8" )){
		if(isosxpkgvuln( fixed: "com.apple.pkg.JavaForMacOSX10.6Update", diff: "5" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}

