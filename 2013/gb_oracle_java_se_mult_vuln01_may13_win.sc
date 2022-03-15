if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803486" );
	script_version( "$Revision: 12047 $" );
	script_cve_id( "CVE-2013-2440", "CVE-2013-2435", "CVE-2013-2433", "CVE-2013-2418", "CVE-2013-2422", "CVE-2013-1558", "CVE-2013-1540", "CVE-2013-1563" );
	script_bugtraq_id( 59124, 59089, 59220, 59145, 59228, 59219, 59149, 59208 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-24 09:38:41 +0200 (Wed, 24 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2013-05-06 16:37:14 +0530 (Mon, 06 May 2013)" );
	script_name( "Oracle Java SE Multiple Vulnerabilities -01 May 13 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/53008" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpuapr2013-1928497.html" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpuapr2013verbose-1928687.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to affect confidentiality,
  integrity, and availability via unknown vectors. Attackers can even execute
  arbitrary code on the target system." );
	script_tag( name: "affected", value: "Oracle Java SE Version 7 Update 17 and earlier and 6 Update 43 and earlier" );
	script_tag( name: "insight", value: "Multiple flaws due to unspecified errors in the Deployment, Libraries,
  Install and Beans components." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer && IsMatchRegexp( jreVer, "^(1\\.(6|7))" )){
	if(version_in_range( version: jreVer, test_version: "1.7", test_version2: "1.7.0.17" ) || version_in_range( version: jreVer, test_version: "1.6", test_version2: "1.6.0.43" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

