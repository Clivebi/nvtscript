if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804846" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2014-0015", "CVE-2014-1317", "CVE-2014-1375", "CVE-2014-1378", "CVE-2014-1355", "CVE-2014-1359", "CVE-2014-1356", "CVE-2014-1357", "CVE-2014-1358", "CVE-2014-1380", "CVE-2014-1381" );
	script_bugtraq_id( 65270, 68272, 68272, 68272, 68274, 68274, 68274, 68274, 68274, 68272, 68272 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2014-09-19 10:06:15 +0530 (Fri, 19 Sep 2014)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities -01 Sep14" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to bypass security restrictions, disclose sensitive information,
  compromise the affected system, conduct privilege escalation and denial of
  service attacks." );
	script_tag( name: "affected", value: "Apple Mac OS X version before 10.9.4" );
	script_tag( name: "solution", value: "Run Mac Updates. Please see the references for more information." );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT1338" );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT6296" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1030505" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2014-06/0172.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.9\\." );
	exit( 0 );
}
require("version_func.inc.sc");
osName = get_kb_item( "ssh/login/osx_name" );
if(!osName){
	exit( 0 );
}
osVer = get_kb_item( "ssh/login/osx_version" );
if(!osVer){
	exit( 0 );
}
if(ContainsString( osName, "Mac OS X" )){
	if(version_in_range( version: osVer, test_version: "10.9.0", test_version2: "10.9.3" )){
		report = report_fixed_ver( installed_version: osVer, vulnerable_range: "10.9.0 - 10.9.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

