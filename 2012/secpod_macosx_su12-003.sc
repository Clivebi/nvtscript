if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.903027" );
	script_version( "2021-08-06T11:34:45+0000" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-08-06 11:34:45 +0000 (Fri, 06 Aug 2021)" );
	script_tag( name: "creation_date", value: "2012-05-21 14:38:50 +0530 (Mon, 21 May 2012)" );
	script_name( "Mac OS X 'Internet plug-ins' Unspecified Vulnerability (2012-003)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/DL1533" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT1222" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5283" );
	script_xref( name: "URL", value: "http://packetstormsecurity.org/files/112742/APPLE-SA-2012-05-14-2.txt" );
	script_xref( name: "URL", value: "http://prod.lists.apple.com/archives/security-announce/2012/May/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_family( "Mac OS X Local Security Checks" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.5\\.[0-8]" );
	script_tag( name: "impact", value: "Unknown impact" );
	script_tag( name: "affected", value: "Internet plug-ins for Adobe Flash Player on Mac OS X" );
	script_tag( name: "solution", value: "Run Mac Updates and update the Security Update 2012-003" );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Mac OS X 10.5.x Update/Mac OS X Security Update 2012-003." );
	script_tag( name: "insight", value: "The flaw is cause due to the unspecified error in the Internet plug-ins.

  Please see the references for more information on the vulnerabilities." );
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
	if(version_in_range( version: osVer, test_version: "10.5.0", test_version2: "10.5.8" )){
		if(isosxpkgvuln( fixed: "com.apple.pkg.update.security.", diff: "2012.003" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}

