CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804345" );
	script_version( "$Revision: 12818 $" );
	script_cve_id( "CVE-2014-2238" );
	script_bugtraq_id( 65903 );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2014-05-13 10:36:53 +0530 (Tue, 13 May 2014)" );
	script_name( "MantisBT 'filter_config_id' SQL Injection Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with MantisBT and is prone to SQL injection
  vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the 'admin_config_report.php' script not properly
  sanitizing user-supplied input to the 'filter_config_id' POST parameter." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote authenticated attacker to inject or
  manipulate SQL queries in the back-end database, allowing for the manipulation
  or disclosure of arbitrary data." );
	script_tag( name: "affected", value: "MantisBT version 1.2.13 through 1.2.16" );
	script_tag( name: "solution", value: "Upgrade to MantisBT version 1.2.17 or later." );
	script_xref( name: "URL", value: "http://seclists.org/oss-sec/2014/q1/490" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125490/MantisBT-1.2.16-SQL-Injection.html" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!manPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!manVer = get_app_version( cpe: CPE, port: manPort )){
	exit( 0 );
}
if(version_in_range( version: manVer, test_version: "1.2.13", test_version2: "1.2.16" )){
	report = report_fixed_ver( installed_version: manVer, fixed_version: "1.2.17" );
	security_message( port: manPort, data: report );
	exit( 0 );
}
exit( 99 );

