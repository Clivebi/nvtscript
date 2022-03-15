CPE = "cpe:/a:vbulletin:vbulletin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108145" );
	script_version( "2021-09-16T09:01:51+0000" );
	script_cve_id( "CVE-2017-7569" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-16 09:01:51 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-12 20:46:00 +0000 (Wed, 12 Apr 2017)" );
	script_tag( name: "creation_date", value: "2017-04-19 07:57:33 +0200 (Wed, 19 Apr 2017)" );
	script_name( "vBulletin 'parse_url' Server Side Request Forgery (SSRF) Vulnerability" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "vbulletin_detect.sc" );
	script_mandatory_keys( "vbulletin/detected" );
	script_xref( name: "URL", value: "https://www.vbulletin.com/forum/forum/vbulletin-announcements/vbulletin-announcements_aa/4367744-vbulletin-5-3-0-connect-is-now-available" );
	script_tag( name: "summary", value: "This host is installed with vBulletin and is prone
  to a server side request forgery vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Remote attackers can bypass the CVE-2016-6483 patch and
  conduct SSRF attacks by leveraging the behavior of the PHP parse_url function, aka VBV-17037." );
	script_tag( name: "affected", value: "vBulletin versions before 5.3.0." );
	script_tag( name: "solution", value: "Upgrade to vBulletin version 5.3.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "5.3.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.3.0", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

