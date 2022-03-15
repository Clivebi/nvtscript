CPE = "cpe:/a:otrs:otrs";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112052" );
	script_version( "2021-09-09T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 11:01:33 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-22 08:26:38 +0200 (Fri, 22 Sep 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-14635" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OTRS Code Injection / Privilege Escalation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_otrs_detect.sc" );
	script_mandatory_keys( "OTRS/installed" );
	script_tag( name: "summary", value: "OTRS is prone to a privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An attacker who is logged into OTRS as an agent with write permissions for statistics can inject arbitrary code into the system.
      This can lead to serious problems like privilege escalation, data loss, and denial of service." );
	script_tag( name: "affected", value: "OTRS 3.3.x before 3.3.18, 4.x before 4.0.25, and 5.x before 5.0.23" );
	script_tag( name: "solution", value: "Upgrade to OTRS 3.3.18, 4.0.25, 5.0.23 or later." );
	script_xref( name: "URL", value: "https://www.otrs.com/security-advisory-2017-04-security-update-otrs-versions/" );
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
if(version_is_less( version: version, test_version: "3.3.18" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.3.18" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0.0", test_version2: "4.0.24" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.0.25" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.0", test_version2: "5.0.22" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.23" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

