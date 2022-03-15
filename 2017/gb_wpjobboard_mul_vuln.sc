CPE = "cpe:/a:wpjobboard:wpjobboard";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107235" );
	script_version( "2020-12-08T08:52:45+0000" );
	script_tag( name: "cvss_base", value: "3.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "last_modification", value: "2020-12-08 08:52:45 +0000 (Tue, 08 Dec 2020)" );
	script_tag( name: "creation_date", value: "2017-09-06 20:31:53 +0530 (Wed, 06 Sep 2017)" );
	script_name( "WpJobBoard Multiple Cross Site Web Vulnerabilities" );
	script_tag( name: "summary", value: "The host is installed with WpJobBoard and is prone to multiple
  cross-site web vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerabilities are located in the query and id parameters of
  the wpjb-email, wpjb-job, wpjb-application and wpjb-membership modules." );
	script_tag( name: "impact", value: "Remote attackers are able to inject own malicious script code to
  hijack admin session credentials via backend or to manipulate the backend on client-side performed
  requests. Attack Vector: Non-persistent." );
	script_tag( name: "affected", value: "WPJobBoard - WordPress Plugin 4.4.4 and 4.5.1." );
	script_tag( name: "solution", value: "Updates are available. Check for fixes supplied by the vendor." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2017/Sep/0" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wpjobboard_detect.sc" );
	script_mandatory_keys( "wpjobboard/installed" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!ver = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: ver, test_version: "4.4.4" ) || version_is_equal( version: ver, test_version: "4.5.1" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "Check for fixes supplied by the vendor" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

