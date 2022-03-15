if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113160" );
	script_version( "2021-06-22T11:00:29+0000" );
	script_tag( name: "last_modification", value: "2021-06-22 11:00:29 +0000 (Tue, 22 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-04-18 14:00:00 +0200 (Wed, 18 Apr 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-18 15:40:00 +0000 (Fri, 18 May 2018)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2017-0356" );
	script_name( "IkiWiki Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ikiwiki_consolidation.sc" );
	script_mandatory_keys( "ikiwiki/detected" );
	script_tag( name: "summary", value: "A flaw, similar to CVE-2016-9646 exists in the passwordauth plugin's use of CGI::FormBuilder,
  allowing an attacker to bypass authentication via repeated parameters" );
	script_tag( name: "vuldetect", value: "The script checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation would allow an attacker to bypass access restrictions." );
	script_tag( name: "affected", value: "IkiWiki before version 3.20170111." );
	script_tag( name: "solution", value: "Update to version 3.20170111." );
	script_xref( name: "URL", value: "https://marc.info/?l=oss-security&m=148418234314276&w=2" );
	script_xref( name: "URL", value: "https://ikiwiki.info/security/#cve-2017-0356" );
	exit( 0 );
}
CPE = "cpe:/a:ikiwiki:ikiwiki";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "3.20170111" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.20170111" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

