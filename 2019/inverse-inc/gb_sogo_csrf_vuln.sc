CPE = "cpe:/a:inverse-inc:sogo";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142121" );
	script_version( "2021-09-07T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2021-09-07 08:01:28 +0000 (Tue, 07 Sep 2021)" );
	script_tag( name: "creation_date", value: "2019-03-11 16:49:48 +0700 (Mon, 11 Mar 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-07 21:56:00 +0000 (Thu, 07 Nov 2019)" );
	script_cve_id( "CVE-2015-5395" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "SOGo < 3.1.0 CSRF Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_inverseinc_sogo_detect.sc" );
	script_mandatory_keys( "inverse/sogo/detected" );
	script_tag( name: "summary", value: "SOGo is prone to a cross-site request forgery vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "SOGo prior to version 3.1.0." );
	script_tag( name: "solution", value: "Upgrade to version 3.1.0 or later." );
	script_xref( name: "URL", value: "https://sogo.nu/bugs/view.php?id=3246" );
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
if(version_is_less( version: version, test_version: "3.1.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.1.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

