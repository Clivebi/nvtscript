if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802798" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-06-26 18:25:17 +0530 (Tue, 26 Jun 2012)" );
	script_name( "Mac OS X Certificate Trust Policy Information Disclosure Vulnerability (2011-005)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT4920" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/DL1446" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2011/Sep/msg00000.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.6\\.8" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to gain sensitive information." );
	script_tag( name: "affected", value: "Certificate Trust Policy" );
	script_tag( name: "insight", value: "The fraudulent certificates were issued by multiple certificate authorities
  operated by DigiNotar." );
	script_tag( name: "solution", value: "Run Mac Updates and update the Security Update 2011-005." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Mac OS X 10.6.8 Update/Mac OS X Security Update 2011-005." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("pkg-lib-macosx.inc.sc");
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
		if(isosxpkgvuln( fixed: "com.apple.pkg.update.security.", diff: "2011.005" )){
			report = report_fixed_ver( installed_version: osVer, vulnerable_range: "Equal to 10.6.8" );
			security_message( port: 0, data: report );
		}
	}
}

