CPE = "cpe:/a:adobe:acrobat";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803829" );
	script_version( "2019-05-17T10:45:27+0000" );
	script_cve_id( "CVE-2012-0776", "CVE-2012-0774", "CVE-2012-0775" );
	script_bugtraq_id( 52952, 52951, 52949 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-05-17 10:45:27 +0000 (Fri, 17 May 2019)" );
	script_tag( name: "creation_date", value: "2013-07-11 15:18:22 +0530 (Thu, 11 Jul 2013)" );
	script_name( "Adobe Acrobat Multiple Vulnerabilities April-2012 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/48733" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1026908" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-08.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Acrobat/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will let attackers to bypass certain security
  restrictions, execute arbitrary code via unspecified vectors or cause a
  denial of service." );
	script_tag( name: "affected", value: "Adobe Acrobat version 9.x to 9.5 and prior and 10.x to 10.1.2 on Windows" );
	script_tag( name: "insight", value: "The flaws are due to

  - An unspecified error when handling JavaScript/JavaScript API can be
    exploited to corrupt memory.

  - An integer overflow error when handling True Type Font (TTF) can be
    exploited to corrupt memory.

  - The application loads executables (msiexec.exe) in an insecure manner." );
	script_tag( name: "solution", value: "Upgrade to Adobe Acrobat version 9.5.1 or 10.1.3 on later." );
	script_tag( name: "summary", value: "This host is installed with Adobe Acrobat and is prone to
  multiple vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "9.0", test_version2: "9.5" ) || version_in_range( version: vers, test_version: "10.0", test_version2: "10.1.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.5.1/10.1.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );
