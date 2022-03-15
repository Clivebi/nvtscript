CPE = "cpe:/a:get-simple:getsimple_cms";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801410" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2010-5052", "CVE-2010-4863" );
	script_bugtraq_id( 41697 );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2010-07-26 16:14:51 +0200 (Mon, 26 Jul 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "GetSimple CMS < 2.03 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_getsimple_cms_http_detect.sc" );
	script_mandatory_keys( "getsimple_cms/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/40428" );
	script_xref( name: "URL", value: "http://seclists.org/bugtraq/2010/May/234" );
	script_tag( name: "insight", value: "The flaws are due to: input passed to various scripts via
  various parameters are not properly sanitized before being returned to the user." );
	script_tag( name: "solution", value: "Update to version 2.03 or later." );
	script_tag( name: "summary", value: "GetSimple CMS is prone to multiple vulnerabilities." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  HTML and script code in a user's browser session in context of an affected site." );
	script_tag( name: "affected", value: "GetSimple CMS version 2.01 and prior." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "2.01" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.03" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

