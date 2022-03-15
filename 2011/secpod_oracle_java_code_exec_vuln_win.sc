if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902349" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-28 11:12:07 +0100 (Mon, 28 Feb 2011)" );
	script_cve_id( "CVE-2010-4467" );
	script_bugtraq_id( 46395 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "Oracle Java SE Code Execution Vulnerability (Windows)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JDK_or_JRE/Win/installed" );
	script_tag( name: "impact", value: "Successful attacks will allow attackers to execute arbitrary code in the
  context of the affected application with system privileges." );
	script_tag( name: "affected", value: "Oracle Java SE 6 Update 10 through 6 Update 23" );
	script_tag( name: "insight", value: "The flaw is due to an error in 'Java Runtime Environment(JRE)', which
  allows remote untrusted Java Web Start applications and untrusted Java
  applets to affect confidentiality, integrity, and availability via unknown
  vectors related to deployment." );
	script_tag( name: "solution", value: "Upgrade to Oracle Java SE 6 Update 24 or later" );
	script_tag( name: "summary", value: "This host is installed with Sun Java SE and is prone to code
  execution vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0405" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpufeb2011-304611.html" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_in_range( version: jreVer, test_version: "1.6.0.10", test_version2: "1.6.0.23" )){
		report = report_fixed_ver( installed_version: jreVer, vulnerable_range: "1.6.0.10 - 1.6.0.23" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
jdkVer = get_kb_item( "Sun/Java/JDK/Win/Ver" );
if(jdkVer){
	if(version_in_range( version: jdkVer, test_version: "1.6.0.10", test_version2: "1.6.0.23" )){
		report = report_fixed_ver( installed_version: jdkVer, vulnerable_range: "1.6.0.10 - 1.6.0.23" );
		security_message( port: 0, data: report );
	}
}

