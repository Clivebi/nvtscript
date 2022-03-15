if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800975" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2009-11-13 15:48:12 +0100 (Fri, 13 Nov 2009)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_cve_id( "CVE-2009-3877", "CVE-2009-3876", "CVE-2009-3875", "CVE-2009-3873", "CVE-2009-3874", "CVE-2009-3872", "CVE-2009-3871", "CVE-2009-3869", "CVE-2009-3868", "CVE-2009-3867" );
	script_bugtraq_id( 36881 );
	script_name( "Sun Java JDK/JRE Multiple Vulnerabilities - Nov09 (Linux)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37231" );
	script_xref( name: "URL", value: "http://java.sun.com/javase/6/webnotes/6u17.html" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3131" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_lin.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Linux/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attacker to execute arbitrary code,
  gain escalated privileges, bypass security restrictions and cause denial
  of service attacks inside the context of the affected system." );
	script_tag( name: "affected", value: "Sun Java JDK/JRE 6 prior to 6 Update 17

  Sun Java JDK/JRE 5 prior to 5 Update 22

  Sun Java JDK/JRE 1.4.x prior to 1.4.2_24

  Sun Java JDK/JRE 1.3.x prior to 1.3.1_27 on Linux." );
	script_tag( name: "insight", value: "Multiple flaws occur due to:

  - Error when decoding 'DER' encoded data and parsing HTTP headers.

  - Error when verifying 'HMAC' digests.

  - Integer overflow error in the 'JPEG JFIF' Decoder while processing
    malicious image files.

  - A buffer overflow error in the 'setDiffICM()' and 'setBytePixels()'
    functions in the Abstract Window Toolkit (AWT).

  - Unspecified error due to improper parsing of color profiles of images.

  - A buffer overflow error due to improper implementation of the
    'HsbParser.getSoundBank()' function.

  - Three unspecified errors when processing audio or image files." );
	script_tag( name: "solution", value: "Upgrade to JDK/JRE version 6 Update 17 or later,

  Upgrade to JDK/JRE version 5 Update 22

  Upgrade to JDK/JRE version 1.4.2_24

  Upgrade to JDK/JRE version 1.3.1_27" );
	script_tag( name: "summary", value: "This host is installed with Sun Java JDK/JRE and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Linux/Ver" );
if(!jreVer){
	exit( 0 );
}
if(version_in_range( version: jreVer, test_version: "1.3", test_version2: "1.3.1.26" ) || version_in_range( version: jreVer, test_version: "1.4", test_version2: "1.4.2.23" ) || version_in_range( version: jreVer, test_version: "1.5", test_version2: "1.5.0.21" ) || version_in_range( version: jreVer, test_version: "1.6", test_version2: "1.6.0.16" )){
	security_message( port: 0, data: "The target host was found to be vulnerable" );
}

