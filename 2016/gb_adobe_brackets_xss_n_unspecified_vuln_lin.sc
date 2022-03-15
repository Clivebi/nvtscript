CPE = "cpe:/a:adobe:brackets";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808186" );
	script_version( "2021-09-20T13:02:01+0000" );
	script_cve_id( "CVE-2016-4164", "CVE-2016-4165" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 13:02:01 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-06-17 13:13:00 +0000 (Fri, 17 Jun 2016)" );
	script_tag( name: "creation_date", value: "2016-07-08 11:10:27 +0530 (Fri, 08 Jul 2016)" );
	script_tag( name: "qod_type", value: "executable_version_unreliable" );
	script_name( "Adobe Brackets Cross-site Scripting and Unspecified Vulnerabilities (Linux)" );
	script_tag( name: "summary", value: "This host is installed with Adobe Brackets
  and is prone to cross-site scripting and an unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - A JavaScript injection vulnerability.

  - An input validation vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow
  remote attackers to inject arbitrary web script or HTML code or have an
  unspecified impact on affected system." );
	script_tag( name: "affected", value: "Adobe Brackets prior to 1.7 on Linux." );
	script_tag( name: "solution", value: "Upgrade to Adobe Brackets version 1.7
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/brackets/apsb16-20.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_brackets_detect_lin.sc" );
	script_mandatory_keys( "Adobe/Brackets/Linux/Ver" );
	script_xref( name: "URL", value: "http://brackets.io" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!BrkVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: BrkVer, test_version: "1.7.0" )){
	report = report_fixed_ver( installed_version: BrkVer, fixed_version: "1.7.0" );
	security_message( data: report );
	exit( 0 );
}

