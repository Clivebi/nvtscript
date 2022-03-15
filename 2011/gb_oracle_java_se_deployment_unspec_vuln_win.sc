if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802278" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_cve_id( "CVE-2011-3516" );
	script_bugtraq_id( 50229 );
	script_tag( name: "cvss_base", value: "7.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-11-15 14:34:22 +0530 (Tue, 15 Nov 2011)" );
	script_name( "Oracle Java SE Java Runtime Environment Unspecified Vulnerability - October 2011 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46512" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JDK_or_JRE/Win/installed" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors." );
	script_tag( name: "affected", value: "Oracle Java SE versions 6 Update 27 and earlier." );
	script_tag( name: "insight", value: "The flaw is due to unspecified error in the 'Deployment' sub-component." );
	script_tag( name: "solution", value: "Upgrade to Oracle Java SE versions 6 Update 29 or later." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to
  unspecified vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_in_range( version: jreVer, test_version: "1.6", test_version2: "1.6.0.27" )){
		report = report_fixed_ver( installed_version: jreVer, vulnerable_range: "1.6 - 1.6.0.27" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
jdkVer = get_kb_item( "Sun/Java/JDK/Win/Ver" );
if(jdkVer){
	if(version_in_range( version: jdkVer, test_version: "1.6", test_version2: "1.6.0.27" )){
		report = report_fixed_ver( installed_version: jdkVer, vulnerable_range: "1.6 - 1.6.0.27" );
		security_message( port: 0, data: report );
	}
}

