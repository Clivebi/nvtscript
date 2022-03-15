CPE = "cpe:/a:adobe:captivate";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811136" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_cve_id( "CVE-2017-3087", "CVE-2017-3098" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-08 01:29:00 +0000 (Sat, 08 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-06-21 18:20:28 +0530 (Wed, 21 Jun 2017)" );
	script_tag( name: "qod", value: "30" );
	script_name( "Adobe Captivate Multiple Vulnerabilities (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Captivate
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due an input validation
  error and secuirty bypass error in the quiz reporting feature." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code on the target system, escalate privileges
  and disclose sensitive information." );
	script_tag( name: "affected", value: "Adobe Captivate prior to 10.0.0.192
  on Windows." );
	script_tag( name: "solution", value: "Upgrade to Captivate version
  10.0.0.192 or later or apply hotfix for Adobe Captivate 8 and 9." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/captivate/apsb17-19.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_captivate_detect.sc" );
	script_mandatory_keys( "Adobe/Captivate/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!digitalVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: digitalVer, test_version: "10.0.0.192" )){
	report = report_fixed_ver( installed_version: digitalVer, fixed_version: "10.0.0.192" );
	security_message( data: report );
	exit( 0 );
}

