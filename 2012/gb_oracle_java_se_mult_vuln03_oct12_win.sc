if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802481" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2012-5087", "CVE-2012-5088", "CVE-2012-5074", "CVE-2012-5076" );
	script_bugtraq_id( 56043, 56057, 56056, 56054 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2012-10-19 12:54:25 +0530 (Fri, 19 Oct 2012)" );
	script_name( "Oracle Java SE JRE Multiple Unspecified Vulnerabilities-03 oct12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50949/" );
	script_xref( name: "URL", value: "http://www.securelist.com/en/advisories/50949" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/javacpuoct2012-1515924.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to execute arbitrary code on
  the target system or cause complete denial of service conditions." );
	script_tag( name: "affected", value: "Oracle Java SE 7 Update 7 and earlier" );
	script_tag( name: "insight", value: "Multiple unspecified vulnerabilities exist in the application related
  to JAX-WS, Beans and Libraries." );
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
	if(version_in_range( version: jreVer, test_version: "1.7", test_version2: "1.7.0.7" )){
		report = report_fixed_ver( installed_version: jreVer, vulnerable_range: "1.7 - 1.7.0.7" );
		security_message( port: 0, data: report );
	}
}

