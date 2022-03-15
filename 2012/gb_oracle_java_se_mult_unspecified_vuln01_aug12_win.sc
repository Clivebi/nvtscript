if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802949" );
	script_version( "$Revision: 11857 $" );
	script_cve_id( "CVE-2012-1725", "CVE-2012-1716" );
	script_bugtraq_id( 53954, 53947 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 10:25:16 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-22 18:44:44 +0530 (Wed, 22 Aug 2012)" );
	script_name( "Oracle Java SE Java Runtime Environment Multiple Unspecified Vulnerabilities(01) - (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48589" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027153" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpujun2012-1515912.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary code on
  the target system or cause complete denial of service conditions." );
	script_tag( name: "affected", value: "Oracle Java SE 7 update 4 and earlier, 6 update 32 and earlier,
  and 5 update 35 and earlier" );
	script_tag( name: "insight", value: "Unspecified vulnerabilities in the application related to Swing and Hotspot." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE and is prone to multiple
  unspecified vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_in_range( version: jreVer, test_version: "1.7", test_version2: "1.7.0.4" ) || version_in_range( version: jreVer, test_version: "1.6", test_version2: "1.6.0.32" ) || version_in_range( version: jreVer, test_version: "1.5", test_version2: "1.5.0.35" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}
exit( 99 );

