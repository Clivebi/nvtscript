if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900820" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-08-24 07:49:31 +0200 (Mon, 24 Aug 2009)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-2717" );
	script_name( "Unsafe Interaction In Sun Java SE Abstract Window Toolkit (Windows)" );
	script_xref( name: "URL", value: "http://java.sun.com/javase/6/webnotes/6u15.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JDK_or_JRE/Win/installed" );
	script_tag( name: "impact", value: "Successful attacks will allow attackers to trick a user into interacting
  unsafely with an untrusted applet." );
	script_tag( name: "affected", value: "Sun Java SE version 6.0 before Update 15 on Windows." );
	script_tag( name: "insight", value: "An error in the Abstract Window Toolkit (AWT) implementation on Windows
  2000 Professional does not provide a Security Warning Icon." );
	script_tag( name: "solution", value: "Upgrade to Java SE version 6 Update 15." );
	script_tag( name: "summary", value: "This host is installed with Sun Java SE and is prone to Unsafe
  Interaction." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("secpod_reg.inc.sc");
require("version_func.inc.sc");
if(hotfix_check_sp( win2k: 5 ) <= 0){
	exit( 0 );
}
jdkVer = get_kb_item( "Sun/Java/JDK/Win/Ver" );
if(jdkVer){
	if(version_in_range( version: jdkVer, test_version: "1.6", test_version2: "1.6.0.14" )){
		report = report_fixed_ver( installed_version: jdkVer, vulnerable_range: "1.6 - 1.6.0.14" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_in_range( version: jreVer, test_version: "1.6", test_version2: "1.6.0.14" )){
		report = report_fixed_ver( installed_version: jreVer, vulnerable_range: "1.6 - 1.6.0.14" );
		security_message( port: 0, data: report );
	}
}

