if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804848" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2014-1370", "CVE-2014-1371" );
	script_bugtraq_id( 68272 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2014-09-19 12:51:15 +0530 (Fri, 19 Sep 2014)" );
	script_name( "Apple Mac OS X Multiple Vulnerabilities -03 Sep14" );
	script_tag( name: "summary", value: "This host is running Apple Mac OS X and
  is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An out of bounds byte swapping error in the handling of 'AppleDouble' files
  in zip archives.

  - An unvalidated array index error in the Dock's handling of messages from
  applications." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  attackers to bypass sandbox restrictions, execution of arbitrary code,
  and conduct denial of service." );
	script_tag( name: "affected", value: "Apple Mac OS X version 10.7.x through
  10.7.5, 10.8.x through 10.8.5 and 10.9.x before 10.9.4" );
	script_tag( name: "solution", value: "Run Mac Updates. Please see the references for more information." );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT1338" );
	script_tag( name: "qod", value: "30" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT6296" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1030505" );
	script_xref( name: "URL", value: "http://archives.neohapsis.com/archives/bugtraq/2014-06/0172.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/osx_name", "ssh/login/osx_version",  "ssh/login/osx_version=^10\\.[7-9]\\." );
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
	if(version_in_range( version: osVer, test_version: "10.9.0", test_version2: "10.9.3" ) || version_in_range( version: osVer, test_version: "10.8.0", test_version2: "10.8.5" ) || version_in_range( version: osVer, test_version: "10.7.0", test_version2: "10.7.5" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

