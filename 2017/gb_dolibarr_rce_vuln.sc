CPE = "cpe:/a:dolibarr:dolibarr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106908" );
	script_version( "2021-09-13T14:16:31+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 14:16:31 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-06-26 15:10:30 +0700 (Mon, 26 Jun 2017)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-06-30 16:21:00 +0000 (Fri, 30 Jun 2017)" );
	script_cve_id( "CVE-2017-9840" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dolibarr ERP/CRM Remote Code Execution Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_mandatory_keys( "dolibarr/detected" );
	script_tag( name: "summary", value: "Dolibarr ERP/CRM allows low-privilege users to upload files of dangerous
types, which can result in arbitrary code execution within the context of the vulnerable application." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Dolibarr ERP/CRM 5.0.3 and prior" );
	script_tag( name: "solution", value: "Update to version 5.0.4." );
	script_xref( name: "URL", value: "https://www.wizlynxgroup.com/security-research-advisories/vuln/WLX-2017-009" );
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
if(version_is_less_equal( version: version, test_version: "5.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

