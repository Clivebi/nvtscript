if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803020" );
	script_version( "2020-04-22T10:27:30+0000" );
	script_cve_id( "CVE-2012-4681", "CVE-2012-1682", "CVE-2012-3136" );
	script_bugtraq_id( 53135, 55336, 55337 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-04-22 10:27:30 +0000 (Wed, 22 Apr 2020)" );
	script_tag( name: "creation_date", value: "2012-09-03 11:54:23 +0530 (Mon, 03 Sep 2012)" );
	script_name( "Oracle Java SE JRE Multiple Remote Code Execution Vulnerabilities - (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50133" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1027458" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/alert-cve-2012-4681-1835715.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_java_prdts_detect_portable_win.sc" );
	script_mandatory_keys( "Sun/Java/JRE/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation allows remote attackers to bypass SecurityManager
  restrictions and execute arbitrary code." );
	script_tag( name: "affected", value: "Oracle Java SE versions 7 Update 6 and earlier" );
	script_tag( name: "insight", value: "- SecurityManager restrictions using
    'com.sun.beans.finder.ClassFinder.findClass' with the forName method to
    access restricted classes and 'reflection with a trusted immediate caller'
    to access and modify private fields.

  - Multiple unspecified vulnerabilities in the JRE component related to
    Beans sub-component." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "summary", value: "This host is installed with Oracle Java SE JRE and is prone to
  multiple remote code execution vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
jreVer = get_kb_item( "Sun/Java/JRE/Win/Ver" );
if(jreVer){
	if(version_in_range( version: jreVer, test_version: "1.7", test_version2: "1.7.0.6" )){
		report = report_fixed_ver( installed_version: jreVer, vulnerable_range: "1.7 - 1.7.0.6" );
		security_message( port: 0, data: report );
	}
}

