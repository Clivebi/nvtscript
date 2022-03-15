if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112261" );
	script_version( "2021-06-30T11:00:43+0000" );
	script_cve_id( "CVE-2014-2294" );
	script_bugtraq_id( 66076 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-30 11:00:43 +0000 (Wed, 30 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-05-22 15:05:00 +0000 (Tue, 22 May 2018)" );
	script_tag( name: "creation_date", value: "2018-04-26 13:50:11 +0200 (Thu, 26 Apr 2018)" );
	script_name( "Open Web Analytics < 1.5.7 PHP Object Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Open Web Analytics and is prone to a PHP object injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Open Web Analytics (OWA) before 1.5.7 allows remote attackers to conduct PHP object injection attacks via a crafted serialized object in the owa_event parameter to queue.php." );
	script_tag( name: "impact", value: "This issue could be exploited to change certain configuration options or create a file containing arbitrary PHP code via specially crafted serialized objects." );
	script_tag( name: "affected", value: "Open Web Analytics before version 1.5.7." );
	script_tag( name: "solution", value: "Update to version 1.5.7 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.openwebanalytics.com/?p=388" );
	script_xref( name: "URL", value: "http://karmainsecurity.com/KIS-2014-03" );
	script_xref( name: "URL", value: "https://secuniaresearch.flexerasoftware.com/advisories/56999" );
	script_xref( name: "URL", value: "https://secuniaresearch.flexerasoftware.com/secunia_research/2014-3/" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_open_web_analytics_detect.sc" );
	script_mandatory_keys( "OpenWebAnalytics/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
CPE = "cpe:/a:openwebanalytics:open_web_analytics";
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.5.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.7" );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

