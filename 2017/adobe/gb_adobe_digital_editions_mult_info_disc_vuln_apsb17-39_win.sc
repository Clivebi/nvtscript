CPE = "cpe:/a:adobe:digital_editions";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812090" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_cve_id( "CVE-2017-11273", "CVE-2017-11297", "CVE-2017-11298", "CVE-2017-11299", "CVE-2017-11300", "CVE-2017-11301" );
	script_bugtraq_id( 101839 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-11-16 10:51:03 +0530 (Thu, 16 Nov 2017)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Digital Editions Multiple Information Disclosure Vulnerabilities - APSB17-39 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Digital Edition
  and is prone to multiple information disclosure vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to unsafe parsing
  of XML external entities, multiple out-of-bounds read errors and memory corruption
  errors." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Adobe Digital Edition prior to 4.5.7
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Digital Edition version
  4.5.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/Digital-Editions/apsb17-39.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_digital_edition_detect_win.sc" );
	script_mandatory_keys( "AdobeDigitalEdition/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!infos = get_app_version_and_location( cpe: CPE, exit_no_version: TRUE )){
	exit( 0 );
}
digitalVer = infos["version"];
digitalPath = infos["location"];
if(version_is_less( version: digitalVer, test_version: "4.5.7" )){
	report = report_fixed_ver( installed_version: digitalVer, fixed_version: "4.5.7", install_path: digitalPath );
	security_message( data: report );
	exit( 0 );
}
exit( 0 );

