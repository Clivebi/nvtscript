CPE = "cpe:/a:elastic:kibana";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811412" );
	script_version( "2021-09-16T10:32:36+0000" );
	script_cve_id( "CVE-2016-10365" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-16 10:32:36 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-19 11:57:00 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2017-07-03 20:40:53 +0530 (Mon, 03 Jul 2017)" );
	script_name( "Elastic Kibana Open Redirect Vulnerability" );
	script_tag( name: "summary", value: "This host is running Elastic Kibana
  and is prone to open redirect vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an improper validation
  in kibana domain." );
	script_tag( name: "impact", value: "Successful exploitation will lead an attacker
  to craft a link in the Kibana domain that redirects to an arbitrary website." );
	script_tag( name: "affected", value: "Elastic Kibana version before 4.6.3
  and 5.0.1" );
	script_tag( name: "solution", value: "Update to Elastic Kibana version
  4.6.3 or 5.0.1 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_xref( name: "URL", value: "https://www.elastic.co/community/security" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_dependencies( "gb_elastic_kibana_detect_http.sc" );
	script_mandatory_keys( "elastic/kibana/detected" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!kibanaPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!kibanaVer = get_app_version( cpe: CPE, port: kibanaPort )){
	exit( 0 );
}
if( version_is_less( version: kibanaVer, test_version: "4.6.3" ) ){
	fix = "4.6.3";
}
else {
	if(IsMatchRegexp( kibanaVer, "(^5\\.)" )){
		if(version_is_less( version: kibanaVer, test_version: "5.0.1" )){
			fix = "5.0.1";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: kibanaVer, fixed_version: fix );
	security_message( data: report, port: kibanaPort );
	exit( 0 );
}
exit( 99 );

