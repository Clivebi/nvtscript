CPE = "cpe:/a:wso2:identity_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140391" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-22 15:30:59 +0700 (Fri, 22 Sep 2017)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 17:54:00 +0000 (Mon, 09 Nov 2020)" );
	script_cve_id( "CVE-2017-14651" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WSO2 Identity Server XSS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wso2_carbon_detect.sc" );
	script_mandatory_keys( "wso2_carbon_identity_server/detected" );
	script_tag( name: "summary", value: "WSO2 Identity Server is prone to a cross-site scripting vulnerability." );
	script_tag( name: "insight", value: "A potential Reflected Cross-Site Scripting (XSS) vulnerability has been
  identified in the Management Console." );
	script_tag( name: "impact", value: "By leveraging an XSS attack, an attacker can make the browser get redirected
  to a malicious website, make changes in the UI of the web page, retrieve information from the browser or harm
  otherwise." );
	script_tag( name: "affected", value: "WSO2 Identity Server 5.3.0 and probably prior." );
	script_tag( name: "solution", value: "Apply the provide patch." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://docs.wso2.com/display/Security/Security+Advisory+WSO2-2017-0265" );
	script_xref( name: "URL", value: "https://github.com/cybersecurityworks/Disclosed/issues/15" );
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
if(version_is_less_equal( version: version, test_version: "5.3.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "Apply patch" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

