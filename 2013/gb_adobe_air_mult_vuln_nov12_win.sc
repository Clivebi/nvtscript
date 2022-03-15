CPE = "cpe:/a:adobe:adobe_air";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803454" );
	script_version( "2020-10-29T15:35:19+0000" );
	script_cve_id( "CVE-2012-5274", "CVE-2012-5275", "CVE-2012-5276", "CVE-2012-5277", "CVE-2012-5278", "CVE-2012-5279", "CVE-2012-5280" );
	script_bugtraq_id( 56412 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-29 15:35:19 +0000 (Thu, 29 Oct 2020)" );
	script_tag( name: "creation_date", value: "2013-03-28 16:57:06 +0530 (Thu, 28 Mar 2013)" );
	script_name( "Adobe Air Multiple Vulnerabilities - November12 (Windows)" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/51213" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-24.html" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "registry" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_flash_player_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air/Win/Installed" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain sensitive
  information or execute arbitrary code in the context of the affected
  application." );
	script_tag( name: "affected", value: "Adobe AIR version 3.4.0.2710 and earlier on Windows" );
	script_tag( name: "insight", value: "Multiple unspecified errors exist due to memory corruption, buffer overflow
  that could lead to code execution." );
	script_tag( name: "solution", value: "Update to Adobe Air version 3.5.0.600 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "This host is installed with Adobe Air and is prone to multiple
  vulnerabilities." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "3.4.0.2710" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.5.0.600", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

