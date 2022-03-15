if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802277" );
	script_version( "2020-04-23T08:43:39+0000" );
	script_cve_id( "CVE-2011-3555" );
	script_bugtraq_id( 50237 );
	script_tag( name: "cvss_base", value: "6.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:C" );
	script_tag( name: "last_modification", value: "2020-04-23 08:43:39 +0000 (Thu, 23 Apr 2020)" );
	script_tag( name: "creation_date", value: "2011-11-15 14:34:22 +0530 (Tue, 15 Nov 2011)" );
	script_name( "Oracle Java SE Java Runtime Environment Unspecified Vulnerability - October 2011 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/46512" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/70838" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpuoct2011-443431.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JDK_or_JRE/Win/installed" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to cause a denial of service." );
	script_tag( name: "affected", value: "Oracle Java SE versions 7." );
	script_tag( name: "insight", value: "The flaw is due to unspecified error in the Java Runtime Environment
  component." );
	script_tag( name: "solution", value: "Upgrade to Oracle Java SE versions 7 Update 1 or later." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to
  unspecified vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_is_equal( version: jreVer, test_version: "1.7.0" )){
		report = report_fixed_ver( installed_version: jreVer, vulnerable_range: "Equal to 1.7.0" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
jdkVer = get_kb_item( "Sun/Java/JDK/Win/Ver" );
if(jdkVer){
	if(version_is_equal( version: jdkVer, test_version: "1.7.0" )){
		report = report_fixed_ver( installed_version: jdkVer, vulnerable_range: "Equal to 1.7.0" );
		security_message( port: 0, data: report );
	}
}

