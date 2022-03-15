CPE = "cpe:/a:dolibarr:dolibarr";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112215" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-02-12 09:37:40 +0100 (Mon, 12 Feb 2018)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-02-26 21:19:00 +0000 (Mon, 26 Feb 2018)" );
	script_cve_id( "CVE-2017-1000509" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dolibarr <= 6.0.2 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dolibarr_detect.sc" );
	script_mandatory_keys( "dolibarr/detected" );
	script_tag( name: "summary", value: "Dolibarr ERP/CRM is prone to a cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Cross Site Scripting (XSS) exists in product details that can result in execution of javascript code.
The payload is saved with no interference from the detector. When visiting the page later, the payload executes." );
	script_tag( name: "affected", value: "Dolibarr ERP/CRM version 6.0.2." );
	script_tag( name: "solution", value: "Update to version 7.0 or later." );
	script_xref( name: "URL", value: "https://github.com/Dolibarr/dolibarr/issues/7727" );
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
if(version_is_less_equal( version: version, test_version: "6.0.2" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

