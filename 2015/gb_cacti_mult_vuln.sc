CPE = "cpe:/a:cacti:cacti";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805664" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2015-4454", "CVE-2015-4342", "CVE-2015-2665", "CVE-2015-2967" );
	script_bugtraq_id( 75270, 75108, 75669 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2015-07-20 10:16:48 +0530 (Mon, 20 Jul 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cacti Multiple Vulnerabilities-June15" );
	script_tag( name: "summary", value: "This host is installed with Cacti and is
  prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - The 'get_hash_graph_template' function in lib/functions.php script in Cacti.

  - An insufficient sanitization of user-supplied data in HTTP request sent to graphs.

  - Unspecified vectors involving a cdef id

  - An insufficient sanitization of user-supplied data in settings.php in Cacti." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to execute arbitrary SQL
commands, inject arbitrary web script or HTML via unspecified vectors." );
	script_tag( name: "affected", value: "Cacti version before 0.8.8d." );
	script_tag( name: "solution", value: "Upgrade to version 0.8.8d or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/75108" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/75270" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/75669" );
	script_xref( name: "URL", value: "https://fortiguard.com/zeroday/FG-VD-15-017" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "cacti_detect.sc" );
	script_mandatory_keys( "cacti/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!cactiVer = get_app_version( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(version_is_less( version: cactiVer, test_version: "0.8.8d" )){
	report = report_fixed_ver( installed_version: cactiVer, fixed_version: "0.8.8d" );
	security_message( data: report, port: http_port );
	exit( 0 );
}
exit( 0 );

