CPE = "cpe:/a:limesurvey:limesurvey";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145428" );
	script_version( "2021-08-17T09:01:01+0000" );
	script_tag( name: "last_modification", value: "2021-08-17 09:01:01 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-23 02:34:17 +0000 (Tue, 23 Feb 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-04 13:59:00 +0000 (Fri, 04 Jun 2021)" );
	script_cve_id( "CVE-2019-25019" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "LimeSurvey < 4.0.0-RC4 SQL Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_limesurvey_detect.sc" );
	script_mandatory_keys( "limesurvey/installed" );
	script_tag( name: "summary", value: "LimeSurvey is prone to an SQL injection vulnerability via the participant model." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "LimeSurvey versions prior to 4.0.0-RC4." );
	script_tag( name: "solution", value: "Update to version 4.0.0-RC4 or later." );
	script_xref( name: "URL", value: "https://github.com/LimeSurvey/LimeSurvey/blob/master/docs/release_notes.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
require("revisions-lib.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(revcomp( a: version, b: "4.0.0rc4" ) < 0){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.0-RC4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

