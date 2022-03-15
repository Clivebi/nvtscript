CPE = "cpe:/a:concrete5:concrete5";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140817" );
	script_version( "2021-05-26T08:25:33+0000" );
	script_tag( name: "last_modification", value: "2021-05-26 08:25:33 +0000 (Wed, 26 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-27 13:37:17 +0700 (Tue, 27 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-22 13:26:00 +0000 (Thu, 22 Mar 2018)" );
	script_cve_id( "CVE-2017-18195" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Concrete5 Authentication Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_concrete5_detect.sc" );
	script_mandatory_keys( "concrete5/installed" );
	script_tag( name: "summary", value: "An issue was discovered in tools/conversations/view_ajax.php in Concrete5.
An unauthenticated user can enumerate comments from all blog posts by POSTing requests to
/index.php/tools/required/conversations/view_ajax with incremental 'cnvID' integers." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Concrete5 prior to version 8.3.0" );
	script_tag( name: "solution", value: "Update to version 8.3.0 or later." );
	script_xref( name: "URL", value: "https://github.com/concrete5/concrete5/releases/tag/8.3.0" );
	script_xref( name: "URL", value: "https://github.com/r3naissance/NSE/blob/master/http-vuln-cve2017-18195.nse" );
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
if(version_is_less( version: version, test_version: "8.3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "8.3.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

