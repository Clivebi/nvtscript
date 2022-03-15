if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802950" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-1726" );
	script_bugtraq_id( 53948 );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-08-22 19:06:04 +0530 (Wed, 22 Aug 2012)" );
	script_name( "Oracle Java SE Java Runtime Environment Unspecified Vulnerability - (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48589" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpufeb2012-366318.html" );
	script_xref( name: "URL", value: "http://www.metasploit.com/modules/exploit/multi/browser/java_atomicreferencearray" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to gain sensitive information." );
	script_tag( name: "affected", value: "Oracle Java SE versions 7 Update 4 and earlier" );
	script_tag( name: "insight", value: "Unspecified errors related to Libraries component." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to
  unspecified vulnerability." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_in_range( version: jreVer, test_version: "1.7", test_version2: "1.7.0.4" )){
		report = report_fixed_ver( installed_version: jreVer, vulnerable_range: "1.7 - 1.7.0.4" );
		security_message( port: 0, data: report );
	}
}

