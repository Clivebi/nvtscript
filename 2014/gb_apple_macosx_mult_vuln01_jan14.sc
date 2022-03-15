if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804060" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2013-5165", "CVE-2013-5166", "CVE-2013-5167", "CVE-2013-5168", "CVE-2013-5169", "CVE-2013-5170", "CVE-2013-5171", "CVE-2013-5172", "CVE-2013-5173", "CVE-2013-5174", "CVE-2013-5175", "CVE-2013-5176", "CVE-2013-5177", "CVE-2013-5178", "CVE-2013-5179", "CVE-2013-5180", "CVE-2013-5181", "CVE-2013-5182", "CVE-2013-5183", "CVE-2013-5184", "CVE-2013-5185", "CVE-2013-5186", "CVE-2013-5187", "CVE-2013-5188", "CVE-2013-5189", "CVE-2013-5190", "CVE-2013-5191", "CVE-2013-5192", "CVE-2013-3949", "CVE-2013-3951", "CVE-2013-3952", "CVE-2013-3953", "CVE-2013-3954", "CVE-2013-5229" );
	script_bugtraq_id( 63313, 63312, 63317, 63322, 63336, 63330, 63314, 63319, 63321, 63329, 63331, 63332, 63339, 63343, 63311, 63347, 63350, 63346, 63349, 63335, 63351, 63316, 63345, 63348, 63353, 63320, 63344, 63352, 60436, 60440, 60439, 60441, 60444, 77576 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-01-20 11:29:14 +0530 (Mon, 20 Jan 2014)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities - 01 Jan14" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to gain escalated privileges,
disclose potentially sensitive information, bypass certain security
restrictions, and compromise a user's system." );
	script_tag( name: "affected", value: "Apple Mac OS X version before 10.9" );
	script_tag( name: "solution", value: "Run Mac Updates and install OS X v10.9 Supplemental Update." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT1222" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/55446" );
	script_xref( name: "URL", value: "http://jvn.jp/en/jp/JVN56210048/index.html" );
	script_xref( name: "URL", value: "http://lists.apple.com/archives/security-announce/2013/Oct/msg00004.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.[0-9]\\." );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(osVer && IsMatchRegexp( osVer, "^10\\.[0-9]\\." )){
	if(ContainsString( osName, "Mac OS X" )){
		if(version_is_less( version: osVer, test_version: "10.9" )){
			security_message( port: 0, data: "The target host was found to be vulnerable" );
			exit( 0 );
		}
	}
}
exit( 99 );

