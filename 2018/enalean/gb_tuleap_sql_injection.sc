CPE = "cpe:/a:enalean:tuleap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108431" );
	script_version( "2021-06-29T11:00:37+0000" );
	script_tag( name: "last_modification", value: "2021-06-29 11:00:37 +0000 (Tue, 29 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-14 16:00:04 +0100 (Wed, 14 Mar 2018)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-25 18:15:00 +0000 (Fri, 25 Sep 2020)" );
	script_cve_id( "CVE-2018-7738" );
	script_name( "Tuleap 'CVE-2018-7538' SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_tuleap_detect.sc" );
	script_mandatory_keys( "tuleap/installed" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2018/Mar/20" );
	script_xref( name: "URL", value: "https://tuleap.net/plugins/tracker/?aid=11192" );
	script_tag( name: "summary", value: "Tuleap is prone to a SQL injection vulnerability in the tracker functionality." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Tuleap does not sanitize properly user inputs when constructing SQL queries for
  a tracker report when a criteria is a cross reference or a permissions on artifact field." );
	script_tag( name: "impact", value: "An attacker with access to a tracker report could execute arbitrary SQL queries." );
	script_tag( name: "affected", value: "Tuleap versions before 9.18." );
	script_tag( name: "solution", value: "Update to 9.18 or later." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_is_less( version: vers, test_version: "9.18" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "9.18" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

