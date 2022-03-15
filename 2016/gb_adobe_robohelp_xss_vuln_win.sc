CPE = "cpe:/a:adobe:robohelp";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809840" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_cve_id( "CVE-2016-7891" );
	script_bugtraq_id( 94878 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-03-07 16:08:00 +0000 (Thu, 07 Mar 2019)" );
	script_tag( name: "creation_date", value: "2016-12-15 16:08:47 +0530 (Thu, 15 Dec 2016)" );
	script_tag( name: "qod_type", value: "registry" );
	script_name( "Adobe RoboHelp Cross Site Scripting Vulnerability (Windows)" );
	script_tag( name: "summary", value: "This host is installed with Adobe RoboHelp
  server and is prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper sanitization of
  user-supplied input." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to
  execute arbitrary script code in the context of the affected website. This may
  allow the attacker to steal cookie-based authentication credentials and to launch
  other attacks." );
	script_tag( name: "affected", value: "Adobe RoboHelp 11 and prior on Windows." );
	script_tag( name: "solution", value: "Apply the hotfix for Adobe RoboHelp from the referenced advisory." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://helpx.adobe.com/security/products/robohelp/apsb16-46.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_adobe_robohelp_detect_win.sc" );
	script_mandatory_keys( "Adobe/RoboHelp/Win/Ver" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!roboVer = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less_equal( version: roboVer, test_version: "11.0" )){
	report = report_fixed_ver( installed_version: roboVer, fixed_version: "Apply the Hotfix" );
	security_message( data: report );
	exit( 0 );
}

