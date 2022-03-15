CPE = "cpe:/a:hp:onboard_administrator";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105056" );
	script_version( "2020-04-28T08:39:12+0000" );
	script_tag( name: "last_modification", value: "2020-04-28 08:39:12 +0000 (Tue, 28 Apr 2020)" );
	script_tag( name: "creation_date", value: "2014-07-04 10:53:22 +0200 (Fri, 04 Jul 2014)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2014-0224" );
	script_bugtraq_id( 67899 );
	script_name( "HP Onboard Administrator < 4.22 Information Disclosure Vulnerability" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/67899" );
	script_xref( name: "URL", value: "http://h20566.www2.hp.com/portal/site/hpsc/template.PAGE/public/kb/docDisplay/?spf_p.tpst=kbDocDisplay&spf_p.prp_kbDocDisplay=wsrp-navigationalState%3DdocId%253Demr_na-c04351097-1%257CdocLocale%253D%257CcalledBy%253D&javax.portlet.begCacheTok=com.vignette.cachetoken&javax.portlet.endCacheTok=com.vignette.cachetoken" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_hp_onboard_administrator_detect.sc" );
	script_mandatory_keys( "hp/onboard_administrator/detected" );
	script_tag( name: "impact", value: "Successfully exploiting this issue may allow attackers to obtain
  sensitive information by conducting a man-in-the-middle attack. This may lead to other attacks." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to version 4.22 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "summary", value: "A potential security vulnerability has been identified with HP BladeSystem
  c-Class Onboard Administrator (OA) running OpenSSL. This vulnerability could be exploited
  remotely to allow the disclosure of information." );
	script_tag( name: "affected", value: "Onboard Administrator versions prior to 4.22." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: vers, test_version: "4.22" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.22" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

