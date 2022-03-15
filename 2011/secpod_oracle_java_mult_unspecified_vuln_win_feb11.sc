if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902344" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)" );
	script_cve_id( "CVE-2010-4447", "CVE-2010-4448", "CVE-2010-4454", "CVE-2010-4462", "CVE-2010-4465", "CVE-2010-4466", "CVE-2010-4469", "CVE-2010-4473", "CVE-2010-4475", "CVE-2010-4476" );
	script_bugtraq_id( 46409, 46398, 46391, 46394, 46406, 46411, 46400, 46403, 46410, 46091 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Oracle Java SE Multiple Unspecified Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0405" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpufeb2011-304611.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JDK_or_JRE/Win/installed" );
	script_tag( name: "impact", value: "Successful attacks will allow attackers to manipulate or gain knowledge of
  sensitive information, bypass restrictions, cause a denial of service or
  compromise a vulnerable system." );
	script_tag( name: "affected", value: "Oracle Java SE 1.4.2_29 and prior,
  Oracle Java SE 6 Update 23 and 5 Update 27 and prior." );
	script_tag( name: "insight", value: "The flaws are due to:

  - Error in 'JRE' allows remote untrusted Java Web Start applications and
    untrusted Java applets to affect confidentiality, integrity via unknown
    vectors related to Deployment and Networking.

  - Error in 'JRE' component, which allows remote attackers to affect
    confidentiality, integrity, and availability via unknown vectors related to
    Sound, Swing, HotSpot and unspecified APIs." );
	script_tag( name: "solution", value: "Upgrade to Oracle Java SE 6 Update 24 or later" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Sun Java SE and is prone to multiple
  unspecified vulnerabilities." );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_is_less_equal( version: jreVer, test_version: "1.4.2.29" ) || version_in_range( version: jreVer, test_version: "1.6", test_version2: "1.6.0.23" ) || version_in_range( version: jreVer, test_version: "1.5", test_version2: "1.5.0.27" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
jdkVer = get_kb_item( "Sun/Java/JDK/Win/Ver" );
if(jdkVer){
	if(version_is_less_equal( version: jdkVer, test_version: "1.4.2.29" ) || version_in_range( version: jdkVer, test_version: "1.6", test_version2: "1.6.0.23" ) || version_in_range( version: jdkVer, test_version: "1.5", test_version2: "1.5.0.27" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
exit( 99 );

