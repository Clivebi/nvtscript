CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802749" );
	script_version( "$Revision: 11905 $" );
	script_cve_id( "CVE-2012-0777", "CVE-2012-0776", "CVE-2012-0774", "CVE-2012-0775" );
	script_bugtraq_id( 52950, 52952, 52951, 52949 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-15 14:43:50 +0200 (Mon, 15 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-04-17 13:03:11 +0530 (Tue, 17 Apr 2012)" );
	script_name( "Adobe Reader Multiple Vulnerabilities April-2012 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to

  - An unspecified error when handling JavaScript/JavaScript API can be exploited
  to corrupt memory.

  - An integer overflow error when handling True Type Font (TTF) can be exploited
  to corrupt memory.

  - The application loads executables (msiexec.exe) in an insecure manner." );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to bypass certain security
  restrictions, execute arbitrary code via unspecified vectors or cause a denial of service." );
	script_tag( name: "affected", value: "Adobe Reader version 9.x to 9.5 and prior and 10.x to 10.1.2 on Mac OS X" );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.5.1 or 10.1.3 or later." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48733" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1026908" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-08.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_macosx.sc" );
	script_mandatory_keys( "Adobe/Reader/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(!IsMatchRegexp( vers, "^(9|10)\\.0" )){
	exit( 99 );
}
path = infos["location"];
if(version_in_range( version: vers, test_version: "9.0", test_version2: "9.5" ) || version_in_range( version: vers, test_version: "10.0", test_version2: "10.1.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.5.1/10.1.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

