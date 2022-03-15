CPE = "cpe:/a:xoops:xoops";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900893" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-20 06:52:52 +0100 (Fri, 20 Nov 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3963" );
	script_bugtraq_id( 36955 );
	script_name( "XOOPS Multiple Unspecified Vulnerabilities - Nov09" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_xoops_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "XOOPS/installed" );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/54181" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/3174" );
	script_xref( name: "URL", value: "http://www.xoops.org/modules/news/article.php?storyid=5064" );
	script_tag( name: "impact", value: "Unknown impact." );
	script_tag( name: "affected", value: "XOOPS version prior to 2.4.0 Final on all running platform." );
	script_tag( name: "insight", value: "The flaws are caused by unspecified errors with unknown impacts and unknown
  attack vectors." );
	script_tag( name: "solution", value: "Upgrade to XOOPS version 2.4.0 Final or later." );
	script_tag( name: "summary", value: "This host is running XOOPS and is prone to multiple unspecified
  vulnerabilities." );
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
if(version_is_less( version: vers, test_version: "2.4.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.4.0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

