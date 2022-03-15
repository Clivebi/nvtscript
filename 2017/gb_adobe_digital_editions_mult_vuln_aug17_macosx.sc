CPE = "cpe:/a:adobe:digital_editions";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811621" );
	script_version( "2021-09-10T10:01:38+0000" );
	script_cve_id( "CVE-2017-11274", "CVE-2017-3091", "CVE-2017-11275", "CVE-2017-11276", "CVE-2017-11277", "CVE-2017-11278", "CVE-2017-11279", "CVE-2017-11280", "CVE-2017-11272" );
	script_bugtraq_id( 100194, 100193 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-10 10:01:38 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-08-16 13:47:00 +0000 (Wed, 16 Aug 2017)" );
	script_tag( name: "creation_date", value: "2017-08-10 16:13:44 +0530 (Thu, 10 Aug 2017)" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_name( "Adobe Digital Editions Multiple Vulnerabilities Aug17 (Mac OS X)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Digital Edition
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A buffer overflow vulnerability.

  - A memory corruption vulnerability.

  - XML External Entity Parsing vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the target system, escalate privileges
  and disclose sensitive information." );
	script_tag( name: "affected", value: "Adobe Digital Edition prior to 4.5.6
  on Mac OS X." );
	script_tag( name: "solution", value: "Upgrade to Adobe Digital Edition version
  4.5.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/Digital-Editions/apsb17-27.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_digital_edition_detect_macosx.sc" );
	script_mandatory_keys( "AdobeDigitalEdition/MacOSX/Version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!digitalVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: digitalVer, test_version: "4.5.6" )){
	report = report_fixed_ver( installed_version: digitalVer, fixed_version: "4.5.6" );
	security_message( data: report );
	exit( 0 );
}

