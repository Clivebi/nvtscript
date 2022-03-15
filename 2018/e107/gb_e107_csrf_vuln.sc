if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.113187" );
	script_version( "2021-06-25T02:00:34+0000" );
	script_tag( name: "last_modification", value: "2021-06-25 02:00:34 +0000 (Fri, 25 Jun 2021)" );
	script_tag( name: "creation_date", value: "2018-05-16 15:14:23 +0200 (Wed, 16 May 2018)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-06-19 16:19:00 +0000 (Tue, 19 Jun 2018)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_cve_id( "CVE-2018-11127" );
	script_name( "e107 < 2.1.8 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "e107_detect.sc" );
	script_mandatory_keys( "e107/installed" );
	script_tag( name: "summary", value: "e107 is prone to a CSRF vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Successful exploitation could result in arbitrary user deletion." );
	script_tag( name: "affected", value: "e107 versions through 2.1.7." );
	script_tag( name: "solution", value: "Update to version 2.1.8 or clone the latest version of the github repository." );
	script_xref( name: "URL", value: "https://github.com/e107inc/e107" );
	script_xref( name: "URL", value: "https://github.com/e107inc/e107/issues/3128" );
	exit( 0 );
}
CPE = "cpe:/a:e107:e107";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2.1.8" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

