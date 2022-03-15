if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902556" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-08-29 16:22:41 +0200 (Mon, 29 Aug 2011)" );
	script_cve_id( "CVE-2010-4422", "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4463", "CVE-2010-4465", "CVE-2010-4467", "CVE-2010-4468", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4473", "CVE-2010-4476" );
	script_bugtraq_id( 46091, 46386, 46387, 46391, 46393, 46394, 46395, 46397, 46398, 46399, 46400, 46402, 46403, 46404, 46406, 46409 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Java for Mac OS X 10.5 Update 9" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4563" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce//2011//Mar/msg00002.html" );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.5\\.8" );
	script_tag( name: "impact", value: "Successful exploitation may allow an untrusted Java applet to execute
  arbitrary code outside the Java sandbox. Visiting a web page containing
  a maliciously crafted untrusted Java applet may lead to arbitrary code
  execution with the privileges of the current user." );
	script_tag( name: "affected", value: "Java for Mac OS X v10.5.8 and Mac OS X Server v10.5.8" );
	script_tag( name: "insight", value: "For more information on the vulnerabilities refer the below links." );
	script_tag( name: "solution", value: "Upgrade to Java for Mac OS X 10.5 Update 9." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Mac OS X 10.5 Update 9." );
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
	if(version_is_equal( version: osVer, test_version: "10.5.8" )){
		if(isosxpkgvuln( fixed: "com.apple.pkg.JavaForMacOSX10.5Update", diff: "9" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}

