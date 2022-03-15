CPE = "cpe:/a:oracle:vm_virtualbox";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804949" );
	script_version( "2019-07-05T09:12:25+0000" );
	script_cve_id( "CVE-2014-6540" );
	script_bugtraq_id( 70493 );
	script_tag( name: "cvss_base", value: "1.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2019-07-05 09:12:25 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2014-11-03 11:52:04 +0530 (Mon, 03 Nov 2014)" );
	script_name( "Oracle Virtualbox WDDM Unspecified Vulnerability Nov14 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Oracle VM
  VirtualBox and is prone to unspecified vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is  due to an error related to
  Graphics driver (WDDM) for Windows Guests subcomponent." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to
  cause denial of service attack." );
	script_tag( name: "affected", value: "VirtualBox version 4.1.x before 4.1.34, 4.2.x
  before 4.2.26, and 4.3.x before 4.3.14 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Oracle VM VirtualBox version
  4.1.34 or 4.2.26 or 4.3.14 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/61582/" );
	script_xref( name: "URL", value: "http://cve.circl.lu/cve/CVE-2014-6540" );
	script_xref( name: "URL", value: "http://www.oracle.com/technetwork/topics/security/cpuoct2014-1972960.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_oracle_virtualbox_detect_macosx.sc" );
	script_mandatory_keys( "Oracle/VirtualBox/MacOSX/Version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!virtualVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(IsMatchRegexp( virtualVer, "^(4\\.(1|2|3))" )){
	if(version_in_range( version: virtualVer, test_version: "4.2.0", test_version2: "4.2.25" ) || version_in_range( version: virtualVer, test_version: "4.3.0", test_version2: "4.3.13" ) || version_in_range( version: virtualVer, test_version: "4.1.0", test_version2: "4.1.33" )){
		security_message( port: 0, data: "The target host was found to be vulnerable" );
		exit( 0 );
	}
}

