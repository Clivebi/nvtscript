CPE = "cpe:/a:tiki:tikiwiki_cms/groupware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800315" );
	script_version( "$Revision: 14010 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-06 09:24:33 +0100 (Wed, 06 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2008-12-15 15:44:51 +0100 (Mon, 15 Dec 2008)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2008-5318", "CVE-2008-5319" );
	script_name( "Tiki Wiki CMS Groupware Input Sanitation Weakness Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_tikiwiki_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "TikiWiki/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow arbitrary code execution in the context
  of an affected site." );
	script_tag( name: "affected", value: "Tiki Wiki CMS Groupware version prior to 2.2 on all running platform" );
	script_tag( name: "insight", value: "The vulnerability is due to input validation error in tiki-error.php
  which fails to sanitise before being returned to the user." );
	script_tag( name: "solution", value: "Upgrade to version 2.2 or later." );
	script_tag( name: "summary", value: "The host is installed with Tiki Wiki CMS Groupware and is prone to input sanitation
  weakness vulnerability." );
	script_xref( name: "URL", value: "http://secunia.com/advisories/32341" );
	script_xref( name: "URL", value: "http://info.tikiwiki.org/tiki-read_article.php?articleId=41" );
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
if(version_is_less( version: vers, test_version: "2.2" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.2" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

