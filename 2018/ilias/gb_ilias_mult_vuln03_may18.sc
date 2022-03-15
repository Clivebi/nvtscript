CPE = "cpe:/a:ilias:ilias";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813200" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_cve_id( "CVE-2018-10306", "CVE-2018-10428" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-19 15:12:00 +0000 (Tue, 19 Jun 2018)" );
	script_tag( name: "creation_date", value: "2018-05-21 14:56:09 +0530 (Mon, 21 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "ILIAS LMS Multiple Vulnerabilities-03 May18" );
	script_tag( name: "summary", value: "This host is installed with ILIAS LMS
  and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - Insufficient validation of input passed via 'invalid date' to
  'Services/Form/classes/class.ilDateDurationInputGUI.php' script and
  'Services/Form/classes/class.ilDateTimeInputGUI.php' script.

  - An unspecified vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to conduct XSS attack and have unspecified impact on affected
  system." );
	script_tag( name: "affected", value: "ILIAS LMS 5.1.x prior to 5.1.26" );
	script_tag( name: "solution", value: "Upgrade to ILIAS LMS 5.1.26 or later. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.ilias.de/docu/ilias.php?ref_id=35&obj_id=116793&from_page=116805&cmd=layout&cmdClass=illmpresentationgui&cmdNode=wc&baseClass=ilLMPresentationGUI" );
	script_xref( name: "URL", value: "https://www.ilias.de" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ilias_detect.sc" );
	script_mandatory_keys( "ilias/installed", "ilias/version" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ilPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: ilPort, exit_no_version: TRUE )){
	exit( 0 );
}
ilVer = infos["version"];
path = infos["location"];
if(IsMatchRegexp( ilVer, "^(5\\.1)" ) && version_is_less( version: ilVer, test_version: "5.1.26" )){
	report = report_fixed_ver( installed_version: ilVer, fixed_version: "5.1.26", install_path: path );
	security_message( data: report, port: ilPort );
	exit( 0 );
}
exit( 0 );

