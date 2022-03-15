CPE = "cpe:/a:pivotx:pivotx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902343" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-02-23 12:24:37 +0100 (Wed, 23 Feb 2011)" );
	script_cve_id( "CVE-2011-1035" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "PivotX 'Reset my password' Feature Data Manipulation Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_pivotx_detect.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "PivotX/Installed" );
	script_xref( name: "URL", value: "http://forum.pivotx.net/viewtopic.php?f=2&t=1967" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0445" );
	script_xref( name: "URL", value: "http://forum.pivotx.net/viewtopic.php?p=10639#p10639" );
	script_xref( name: "URL", value: "http://blog.pivotx.net/2011-02-16/pivotx-225-released" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to gain privileges via
  unknown vectors." );
	script_tag( name: "affected", value: "PivotX version before 2.2.5" );
	script_tag( name: "insight", value: "This issue is caused by an error in the 'Reset my password' feature, which
  could allow unauthenticated attackers to change the password of any account
  by guessing the username." );
	script_tag( name: "solution", value: "Upgrade to PivotX version 2.2.5 or later" );
	script_tag( name: "summary", value: "This host is running PivotX and is prone to data manipulation
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://pivotx.net/" );
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
if(version_is_less( version: vers, test_version: "2.2.5" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.2.5" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

