CPE = "cpe:/a:op5:monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103905" );
	script_bugtraq_id( 65244 );
	script_cve_id( "CVE-2013-6141" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_version( "2020-12-07T13:33:44+0000" );
	script_name( "op5 Monitor Unspecified Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/65244" );
	script_xref( name: "URL", value: "https://bugs.op5.com/view.php?id=7677" );
	script_tag( name: "last_modification", value: "2020-12-07 13:33:44 +0000 (Mon, 07 Dec 2020)" );
	script_tag( name: "creation_date", value: "2014-02-11 12:56:33 +0100 (Tue, 11 Feb 2014)" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_op5_detect.sc" );
	script_mandatory_keys( "OP5/installed" );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow an attacker to obtain
  sensitive information that may aid in further attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Unspecified vulnerability in op5 Monitor before 6.1.3 allows
  attackers to read arbitrary files via unknown vectors related to lack of authorization." );
	script_tag( name: "solution", value: "Updates are available." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "op5 Monitor is prone to an unspecified information-disclosure
  vulnerability." );
	script_tag( name: "affected", value: "op5 Monitor 6.1.3 is vulnerable. Other versions may also be affected." );
	exit( 0 );
}
require("http_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_app_version( cpe: CPE, port: port )){
	if(version_is_less( version: vers, test_version: "6.1.3" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "6.1.3" );
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

