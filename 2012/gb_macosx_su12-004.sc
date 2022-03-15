if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802968" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-0021", "CVE-2012-0031", "CVE-2012-0053", "CVE-2012-0650", "CVE-2012-1173", "CVE-2012-3719", "CVE-2012-0831", "CVE-2012-1172", "CVE-2012-1823", "CVE-2012-2143", "CVE-2012-2311", "CVE-2012-2386", "CVE-2012-2688", "CVE-2012-0671", "CVE-2012-0670", "CVE-2012-3722", "CVE-2012-0668", "CVE-2011-3368", "CVE-2011-3607", "CVE-2011-4317", "CVE-2011-3026", "CVE-2011-3048", "CVE-2011-4599", "CVE-2011-3389", "CVE-2012-1667", "CVE-2012-3718", "CVE-2012-3720" );
	script_bugtraq_id( 51705, 51407, 51706, 55623, 52891, 55623, 51954, 53403, 49778, 53388, 53729, 47545, 54638, 53584, 53582, 55612, 49957, 50494, 50802, 52049, 52830, 51006, 52830 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-09-25 19:33:16 +0530 (Tue, 25 Sep 2012)" );
	script_name( "Mac OS X v10.6.8 Multiple Vulnerabilities (2012-004)" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5501" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/DL1586" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50628/" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2012/Sep/msg00004.html" );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Mac OS X Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.6\\.8" );
	script_tag( name: "impact", value: "Successful exploitation could allow attackers to cause a buffer overflow,
  disclose potentially sensitive information or cause a DoS." );
	script_tag( name: "affected", value: "Apache
  BIND
  CoreText
  Data Security
  DirectoryService
  ImageIO
  Installer
  International Components for Unicode
  Kernel
  LoginWindow
  Mail
  Mobile Accounts
  PHP
  Profile Manager
  QuickLook
  QuickTime
  Ruby
  USB" );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "solution", value: "Run Mac Updates and update the Security Update 2012-004." );
	script_tag( name: "summary", value: "This host is missing an important security update according to
  Mac OS X 10.6.8 Update/Mac OS X Security Update 2012-004." );
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
		if(isosxpkgvuln( fixed: "com.apple.pkg.update.security.", diff: "2012.004" )){
			report = report_fixed_ver( installed_version: osVer, vulnerable_range: "Equal to 10.6.8" );
			security_message( port: 0, data: report );
		}
	}
}

