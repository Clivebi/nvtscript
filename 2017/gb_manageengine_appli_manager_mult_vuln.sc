CPE = "cpe:/a:zohocorp:manageengine_applications_manager";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140296" );
	script_version( "2021-09-14T08:01:37+0000" );
	script_tag( name: "last_modification", value: "2021-09-14 08:01:37 +0000 (Tue, 14 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-14 15:43:15 +0700 (Mon, 14 Aug 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)" );
	script_cve_id( "CVE-2016-9488", "CVE-2016-9489", "CVE-2016-9490", "CVE-2016-9498" );
	script_bugtraq_id( 97394 );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "ManageEngine Applications Manager < 13200 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_manage_engine_appli_manager_detect.sc" );
	script_mandatory_keys( "zohocorp/manageengine_applications_manager/detected" );
	script_tag( name: "summary", value: "ManageEngine Applications Manager is prone to multiple vulnerabilities." );
	script_tag( name: "insight", value: "ManageEngine Applications Manager is prone to multiple vulnerabilities:

  - Java RMI Remote Code Execution (CVE-2016-9498)

  - SQL Injection (CVE-2016-9488)

  - Authorization Bypass / Privilege Escalation (CVE-2016-9489)

  - Reflected Cross-Site Scripting (CVE-2016-9490)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "ManageEngine Applications Manager 12 and 13." );
	script_tag( name: "solution", value: "Update to version 13200 or later." );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Apr/9" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "13200" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "13200" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

