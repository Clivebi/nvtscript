CPE = "cpe:/a:open-xchange:open-xchange_appsuite";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806073" );
	script_version( "2019-07-24T11:36:46+0000" );
	script_cve_id( "CVE-2014-2391", "CVE-2014-2392" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2019-07-24 11:36:46 +0000 (Wed, 24 Jul 2019)" );
	script_tag( name: "creation_date", value: "2015-10-06 12:24:33 +0530 (Tue, 06 Oct 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Open-Xchange (OX) AppSuite Multiple Security Bypass Vulnerabilities Oct15" );
	script_tag( name: "summary", value: "The host is installed with
  Open-Xchange (OX) AppSuite and is prone to multiple security bypass
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws exist due to password
  recovery service and E-Mail autoconfiguration feature does not handle password
  properly." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers
  to obtain potentially useful password-pattern information ." );
	script_tag( name: "affected", value: "Open-Xchange (OX) AppSuite versins before
  7.2.2-rev20, 7.4.1 before 7.4.1-rev11, and 7.4.2 before 7.4.2-rev13" );
	script_tag( name: "solution", value: "Upgrade to Open-Xchange (OX) AppSuite
  version 7.2.2-rev20, 7.4.1-rev11, 7.4.2-rev13 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/531762" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ox_app_suite_detect.sc" );
	script_mandatory_keys( "open_xchange_appsuite/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!oxPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!oxVer = get_app_version( cpe: CPE, port: oxPort )){
	;
}
exit( 0 );
oxRev = get_kb_item( "open_xchange_appsuite/" + oxPort + "/revision" );
if(oxRev){
	oxVer = oxVer + "." + oxRev;
	if(version_is_less( version: oxVer, test_version: "7.2.2.20" )){
		fix = "7.2.2.20";
		VULN = TRUE;
	}
	if( version_in_range( version: oxVer, test_version: "7.4.2", test_version2: "7.4.2.12" ) ){
		fix = "7.4.2.13";
		VULN = TRUE;
	}
	else {
		if(version_in_range( version: oxVer, test_version: "7.4.1", test_version2: "7.4.1.10" )){
			fix = "7.4.1.11";
			VULN = TRUE;
		}
	}
	if(VULN){
		report = report_fixed_ver( installed_version: oxVer, fixed_version: fix );
		security_message( port: oxPort, data: report );
		exit( 0 );
	}
}
exit( 99 );

