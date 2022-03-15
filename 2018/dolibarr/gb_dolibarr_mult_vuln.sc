CPE = "cpe:/a:dolibarr:dolibarr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112216" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-12 10:00:40 +0100 (Mon, 12 Feb 2018)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-09 16:11:00 +0000 (Tue, 09 Jan 2018)" );
	script_cve_id( "CVE-2017-17900", "CVE-2017-17898", "CVE-2017-17899", "CVE-2017-17897" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dolibarr < 6.0.5 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_mandatory_keys( "dolibarr/detected" );
	script_tag( name: "summary", value: "Dolibarr ERP/CRM is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The following vulnerabilities exist:

  - SQL injection vulnerability in fourn/index.php allows remote attackers to execute arbitrary SQL commands via the socid parameter. (CVE-2017-17900)

  - Dolibarr does not block direct requests to *.tpl.php files, which allows remote attackers to obtain sensitive information. (CVE-2017-17898)

  - SQL injection vulnerability in adherents/subscription/info.php allows remote attackers to execute arbitrary SQL commands via the rowid parameter. (CVE-2017-17899)

  - SQL injection vulnerability in comm/multiprix.php in Dolibarr ERP/CRM version 6.0.4 allows remote attackers to execute arbitrary SQL commands via the id parameter. (CVE-2017-17897)" );
	script_tag( name: "affected", value: "Dolibarr ERP/CRM version 6.0.4 and prior." );
	script_tag( name: "solution", value: "Upgrade to Dolibarr version 6.0.5." );
	script_xref( name: "URL", value: "https://github.com/Dolibarr/dolibarr/blob/develop/ChangeLog" );
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
if(version_is_less( version: version, test_version: "6.0.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "6.0.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

