if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800427" );
	script_version( "2020-10-19T15:33:20+0000" );
	script_cve_id( "CVE-2009-3953", "CVE-2009-3954", "CVE-2009-3955", "CVE-2009-3956", "CVE-2009-3957", "CVE-2009-3958", "CVE-2009-3959", "CVE-2009-4324", "CVE-2010-1278" );
	script_bugtraq_id( 37758, 37761, 37757, 37763, 37760, 37759, 37756, 39615 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-19 15:33:20 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2010-01-16 12:13:24 +0100 (Sat, 16 Jan 2010)" );
	script_name( "Adobe Reader/Acrobat Multiple Vulnerabilities - Jan10 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader/Acrobat and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause memory corruption or
  denial of service." );
	script_tag( name: "affected", value: "Adobe Reader and Acrobat 9.x before 9.3, 8.x before 8.2 on Windows." );
	script_tag( name: "solution", value: "Update to Adobe Reader and Acrobat 8.2, 9.3 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb10-02.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Air_or_Flash_or_Reader_or_Acrobat/Win/Installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:adobe:acrobat_reader",
	 "cpe:/a:adobe:acrobat" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "9.0", test_version2: "9.2" ) || version_in_range( version: vers, test_version: "8.0", test_version2: "8.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "8.2 or 9.3", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

