CPE = "cpe:/a:apple:itunes";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803765" );
	script_version( "2020-02-28T13:41:47+0000" );
	script_cve_id( "CVE-2013-1035" );
	script_bugtraq_id( 62486 );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-02-28 13:41:47 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2013-09-27 15:45:01 +0530 (Fri, 27 Sep 2013)" );
	script_name( "Apple iTunes ActiveX Control Memory Corruption Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Apple iTunes and is prone to memory corruption
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to Apple iTunes version 11.1 or later." );
	script_tag( name: "insight", value: "The flaw is due to an error within an ActiveX Control." );
	script_tag( name: "affected", value: "Apple iTunes before 11.1 on Windows." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code and
  or cause denial of service." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://support.apple.com/kb/HT5936" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/54893" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2013/Sep/84" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_apple_itunes_detection_win_900123.sc" );
	script_mandatory_keys( "iTunes/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "11.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.1", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

