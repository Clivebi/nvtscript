CPE = "cpe:/h:intel:active_management_technology";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811809" );
	script_version( "2021-09-14T10:02:44+0000" );
	script_cve_id( "CVE-2017-5698" );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:C/A:N" );
	script_tag( name: "last_modification", value: "2021-09-14 10:02:44 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:H/UI:N/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-09-12 19:05:54 +0530 (Tue, 12 Sep 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Intel Active Management Technology Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Intel Active
  Management Technology and is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified error in
  an unspecified function." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct privilege escalation." );
	script_tag( name: "affected", value: "Intel Active Management Technology firmware
  versions 11.0.25.3001 and 11.0.26.3000." );
	script_tag( name: "solution", value: "Upgrade to firmware version 11.6.x.1xxx
  or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00082.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_intel_amt_webui_detect.sc" );
	script_mandatory_keys( "intel_amt/installed" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(vers == "11.0.25.3001" || vers == "11.0.26.3000"){
	report = report_fixed_ver( installed_version: vers, fixed_version: "11.6.x.1xxx or later" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

