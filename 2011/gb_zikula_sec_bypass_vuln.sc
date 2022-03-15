CPE = "cpe:/a:zikula:zikula_application_framework";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.801744" );
	script_version( "$Revision: 14168 $" );
	script_cve_id( "CVE-2010-4728" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 09:10:09 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2011-02-15 08:14:35 +0100 (Tue, 15 Feb 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_name( "Zikula Security Bypass Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2011 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_zikula_detect.sc" );
	script_mandatory_keys( "zikula/detected" );
	script_xref( name: "URL", value: "http://code.zikula.org/core/ticket/2009" );
	script_tag( name: "insight", value: "The flaw exists due to errors in 'rand' and 'srand' PHP functions for random
  number generation." );
	script_tag( name: "solution", value: "Upgrade to the Zikula version 1.3.1." );
	script_tag( name: "summary", value: "This host is running Zikula and is prone to a security bypass
  vulnerability." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to defeat protection
  mechanisms based on randomization by predicting a return value." );
	script_tag( name: "affected", value: "Zikula version prior to 1.3.1." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less( version: vers, test_version: "1.3.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.3.1", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

