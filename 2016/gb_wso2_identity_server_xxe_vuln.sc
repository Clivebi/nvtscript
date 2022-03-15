CPE = "cpe:/a:wso2:identity_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106343" );
	script_version( "2020-08-28T06:35:58+0000" );
	script_cve_id( "CVE-2016-4311", "CVE-2016-4312" );
	script_tag( name: "last_modification", value: "2020-08-28 06:35:58 +0000 (Fri, 28 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-10-10 12:16:07 +0700 (Mon, 10 Oct 2016)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "WSO2 Identity Server CSRF And XXE Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_wso2_carbon_detect.sc" );
	script_mandatory_keys( "wso2_carbon_identity_server/detected" );
	script_tag( name: "summary", value: "WSO2 Identity Server is prone to a XML External Entity vulnerability." );
	script_tag( name: "insight", value: "WSO2 Identity Server is vulnerable to XXE attack which is a type of attack
  against an application that parses XML input. When Identity Server used with its XACML feature, it parses
  XACML requests and XACML policies which contain XML entries according to the XACML specification. This attack
  occurs when a XACML request or a policy containing a reference to an external entity is processed by a weakly
  configured XML parser." );
	script_tag( name: "impact", value: "An authenticated attacker may disclose local files, conduct adenial of
  service and server-side request forgery, port scanning and other system impacts on affected systems." );
	script_tag( name: "affected", value: "WSO2 Identity Server 5.1.0." );
	script_tag( name: "solution", value: "Apply the provide patch or upgrade to 5.2.0 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
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
if(version_is_equal( version: version, test_version: "5.1.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.2.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

