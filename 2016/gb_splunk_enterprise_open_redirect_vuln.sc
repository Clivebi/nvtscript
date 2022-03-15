CPE = "cpe:/a:splunk:splunk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809013" );
	script_version( "2021-09-17T14:01:43+0000" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-17 14:01:43 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-05-19 18:49:00 +0000 (Fri, 19 May 2017)" );
	script_tag( name: "creation_date", value: "2016-08-26 17:00:30 +0530 (Fri, 26 Aug 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Splunk Enterprise Open Redirection Vulnerability" );
	script_cve_id( "CVE-2016-4859" );
	script_tag( name: "summary", value: "This host is installed with Splunk
  Enterprise and is prone to an open redirection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an unspecified input
  validation error." );
	script_tag( name: "impact", value: "Successful exploitation of this vulnerability
  could permit an attacker to redirect a user to an attacker controlled website." );
	script_tag( name: "affected", value: "Splunk Enterprise versions 6.4.x before
  6.4.3, 6.3.x before 6.3.6, 6.2.x before 6.2.10, 6.1.x before 6.1.11, 6.0.x
  before 6.0.12, 5.0.x before 5.0.16" );
	script_tag( name: "solution", value: "Upgrade to Splunk Enterprise version 6.4.3
  or 6.3.6 or 6.2.10 or 6.1.11 or 6.0.12 or 5.0.16 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.splunk.com/view/SP-CAAAPQ6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_splunk_detect.sc" );
	script_mandatory_keys( "Splunk/installed" );
	script_require_ports( "Services/www", 8000 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!splport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!splver = get_app_version( cpe: CPE, port: splport )){
	exit( 0 );
}
if( version_in_range( version: splver, test_version: "6.4.0", test_version2: "6.4.2" ) ){
	fix = "6.4.3";
	VULN = TRUE;
}
else {
	if( version_in_range( version: splver, test_version: "6.3.0", test_version2: "6.3.5" ) ){
		fix = "6.3.6";
		VULN = TRUE;
	}
	else {
		if( version_in_range( version: splver, test_version: "6.1.0", test_version2: "6.1.10" ) ){
			fix = "6.1.11";
			VULN = TRUE;
		}
		else {
			if( version_in_range( version: splver, test_version: "6.2.0", test_version2: "6.2.9" ) ){
				fix = "6.2.10";
				VULN = TRUE;
			}
			else {
				if( version_in_range( version: splver, test_version: "6.0", test_version2: "6.0.11" ) ){
					fix = "6.0.12";
					VULN = TRUE;
				}
				else {
					if(version_in_range( version: splver, test_version: "5.0", test_version2: "5.0.15" )){
						fix = "5.0.16";
						VULN = TRUE;
					}
				}
			}
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: splver, fixed_version: fix );
	security_message( data: report, port: splport );
	exit( 0 );
}
exit( 99 );

