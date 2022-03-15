CPE = "cpe:/a:adobe:acrobat_reader";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.802936" );
	script_version( "$Revision: 11905 $" );
	script_cve_id( "CVE-2012-4149", "CVE-2012-4148", "CVE-2012-4147", "CVE-2012-2051", "CVE-2012-2050", "CVE-2012-4160", "CVE-2012-2049", "CVE-2012-4159", "CVE-2012-4158", "CVE-2012-4157", "CVE-2012-4156", "CVE-2012-4155", "CVE-2012-4154", "CVE-2012-4153", "CVE-2012-1525", "CVE-2012-4152", "CVE-2012-4151", "CVE-2012-4150" );
	script_bugtraq_id( 55008, 55007, 55006, 55005, 55026, 55021, 55024, 55020, 55019, 55018, 55017, 55016, 55015, 55012, 55027, 55013, 55010, 55011 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-15 14:43:50 +0200 (Mon, 15 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2012-08-20 11:01:35 +0530 (Mon, 20 Aug 2012)" );
	script_name( "Adobe Reader Multiple Vulnerabilities - Windows" );
	script_tag( name: "summary", value: "This host is installed with Adobe Reader and is prone to multiple
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaws are due to unspecified errors which can be exploited to corrupt memory." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary code in
  the context of the affected application or cause a denial of service." );
	script_tag( name: "affected", value: "Adobe Reader versions 9.x through 9.5.1 and 10.x through 10.1.3 on Windows" );
	script_tag( name: "solution", value: "Upgrade to Adobe Reader version 9.5.2 or 10.1.4 or later." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/50281" );
	script_xref( name: "URL", value: "http://www.adobe.com/support/security/bulletins/apsb12-16.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_adobe_prdts_detect_win.sc" );
	script_mandatory_keys( "Adobe/Reader/Win/Installed" );
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
if(version_in_range( version: vers, test_version: "9.0", test_version2: "9.5.1" ) || version_in_range( version: vers, test_version: "10.0", test_version2: "10.1.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.5.2/10.1.4", install_path: path );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

