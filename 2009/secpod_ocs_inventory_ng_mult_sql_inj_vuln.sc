CPE = "cpe:/a:ocsinventory-ng:ocs_inventory_ng";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900938" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3040" );
	script_bugtraq_id( 35152 );
	script_name( "OCS Inventory NG Multiple SQL Injection Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_ocs_inventory_ng_detect.sc" );
	script_mandatory_keys( "ocs_inventory_ng/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/503936/100/0/threaded" );
	script_xref( name: "URL", value: "http://www.leidecker.info/advisories/2009-05-30-ocs_inventory_ng_sql_injection.shtml" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to inject arbitrary SQL
  code and obtain sensitive information about system configurations and software on the network." );
	script_tag( name: "affected", value: "OCS Inventory NG version 1.02." );
	script_tag( name: "insight", value: "The user supplied input passedd into 'N', 'DL', 'O', 'v' parameters in
  download.php and 'systemid' parameter in group_show.php file is not sanitised before being used in an SQL query." );
	script_tag( name: "summary", value: "This host is running OCS Inventory NG and is prone to multiple
  SQL Injection vulnerabilities." );
	script_tag( name: "solution", value: "Upgrade to version 1.02.1 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_app" );
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
if(version_is_less( version: vers, test_version: "1.02.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "1.02.1", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

