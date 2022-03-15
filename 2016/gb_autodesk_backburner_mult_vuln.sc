CPE = "cpe:/a:autodesk:autodesk_backburner";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808172" );
	script_version( "2021-09-17T13:01:55+0000" );
	script_cve_id( "CVE-2016-2344" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 13:01:55 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-03 03:25:00 +0000 (Sat, 03 Dec 2016)" );
	script_tag( name: "creation_date", value: "2016-06-21 18:29:15 +0530 (Tue, 21 Jun 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Autodesk Backburner Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with Autodesk
  Backburner and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to a stack-based
  buffer overflow in manager.exe in Backburner Manager in Autodesk Backburner." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute arbitrary code or cause a denial of service." );
	script_tag( name: "affected", value: "Autodesk Backburner version
  2016.0.0.2150 and earlier." );
	script_tag( name: "solution", value: "As a workaround Restrict access to the
  Backburner manager.exe service to trusted users and networks." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/732760" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_autodesk_backburner_detect.sc" );
	script_mandatory_keys( "Autodesk/Backburner/detected" );
	script_xref( name: "URL", value: "https://knowledge.autodesk.com" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!back_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!backVer = get_app_version( cpe: CPE, port: back_port )){
	exit( 0 );
}
if(version_is_less_equal( version: backVer, test_version: "2016.0.0.2150" )){
	report = report_fixed_ver( installed_version: backVer, fixed_version: "Workaround" );
	security_message( data: report, port: back_port );
	exit( 0 );
}

