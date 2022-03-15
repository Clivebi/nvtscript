CPE = "cpe:/a:adobe:digital_editions";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807473" );
	script_version( "2019-07-05T09:54:18+0000" );
	script_cve_id( "CVE-2016-0954" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2019-07-05 09:54:18 +0000 (Fri, 05 Jul 2019)" );
	script_tag( name: "creation_date", value: "2016-03-10 11:12:19 +0530 (Thu, 10 Mar 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe Digital Editions Code Execution Vulnerability March16 (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Digital Edition
  and is prone to code execution Vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to memory leak vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code." );
	script_tag( name: "affected", value: "Adobe Digital Edition 4.x before 4.5.1 on Windows." );
	script_tag( name: "solution", value: "Upgrade to Adobe Digital Edition version 4.5.1
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/Digital-Editions/apsb16-06.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_digital_edition_detect_win.sc" );
	script_mandatory_keys( "AdobeDigitalEdition/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!readerVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_in_range( version: readerVer, test_version: "4.0.0", test_version2: "4.5.0" )){
	report = report_fixed_ver( installed_version: readerVer, fixed_version: "4.5.1" );
	security_message( data: report );
	exit( 0 );
}

