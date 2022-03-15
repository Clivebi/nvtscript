CPE = "cpe:/a:invoiceplane:invoiceplane";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140858" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-03-06 10:57:13 +0700 (Tue, 06 Mar 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-26 13:23:00 +0000 (Fri, 26 Apr 2019)" );
	script_cve_id( "CVE-2017-18217" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "InvoicePlane < 1.5.5 XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_invoiceplane_detect.sc" );
	script_mandatory_keys( "invoiceplane/installed" );
	script_tag( name: "summary", value: "An issue was discovered in InvoicePlane. It was observed that the Email
address and Web address parameters are vulnerable to Cross Site Scripting, related to
application/modules/clients/views/view.php, application/modules/invoices/views/view.php, and
application/modules/quotes/views/view.php." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "InvoicePlane prior to version 1.5.5." );
	script_tag( name: "solution", value: "Update to version 1.5.5 or later." );
	script_xref( name: "URL", value: "https://github.com/InvoicePlane/InvoicePlane/pull/542" );
	script_xref( name: "URL", value: "https://github.com/InvoicePlane/InvoicePlane/pull/551" );
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
if(version_is_less( version: version, test_version: "1.5.5" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

