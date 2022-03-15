if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803334" );
	script_version( "$Revision: 11855 $" );
	script_cve_id( "CVE-2011-3563", "CVE-2012-0499", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506" );
	script_bugtraq_id( 52011, 52012, 52014, 52016, 52017, 52018 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 09:34:51 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-02-21 16:16:16 +0530 (Tue, 21 Feb 2012)" );
	script_name( "Oracle Java SE JDK Multiple Vulnerabilities - February 2012 (Windows - 01)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48009" );
	script_xref( name: "URL", value: "http://www.pre-cert.de/advisories/PRE-SA-2012-01.txt" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/java/javase/documentation/overview-142120.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/java/javase/documentation/overview-137139.html" );
	script_tag( name: "qod_type", value: "registry" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JDK/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Java SE JDK 7 Update 2 and earlier, 6 Update 30 and earlier, 5.0 Update 33
  and earlier, and 1.4.2_35 and earlier" );
	script_tag( name: "insight", value: "Multiple flaws are caused by unspecified errors in the following
  components:

  - 2D

  - AWT

  - Sound

  - I18n

  - CORBA

  - Serialization" );
	script_tag( name: "solution", value: "Upgrade to Oracle Java SE JDK versions 7 Update 3, 6 Update 31, 5.0 Update
  34, 1.4.2_36 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE JDK and is prone to
  multiple vulnerabilities." );
	exit( 0 );
}
require("version_func.inc.sc");
jdkVer = get_kb_item( "Sun/Java/JDK/Win/Ver" );
if(jdkVer){
	if(version_is_less_equal( version: jdkVer, test_version: "1.4.2.35" ) || version_in_range( version: jdkVer, test_version: "1.7", test_version2: "1.7.0.2" ) || version_in_range( version: jdkVer, test_version: "1.6", test_version2: "1.6.0.30" ) || version_in_range( version: jdkVer, test_version: "1.5", test_version2: "1.5.0.33" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
exit( 99 );

