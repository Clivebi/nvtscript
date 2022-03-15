CPE = "cpe:/a:mantisbt:mantisbt";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804650" );
	script_version( "$Revision: 12818 $" );
	script_cve_id( "CVE-2013-1883" );
	script_bugtraq_id( 58626 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2018-12-18 10:55:03 +0100 (Tue, 18 Dec 2018) $" );
	script_tag( name: "creation_date", value: "2014-06-23 15:25:38 +0530 (Mon, 23 Jun 2014)" );
	script_name( "MantisBT 'View Issues' Page Denial of Service Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with MantisBT and is prone to Denial of Service
vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to an error in the filter_api.php script." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attacker to consume all available
memory resources and cause a denial of service condition." );
	script_tag( name: "affected", value: "MantisBT version 1.2.12 through 1.2.14" );
	script_tag( name: "solution", value: "Upgrade to MantisBT version 1.2.15 or later." );
	script_xref( name: "URL", value: "http://xforce.iss.net/xforce/xfdb/83347" );
	script_xref( name: "URL", value: "http://www.mantisbt.org/bugs/view.php?id=15573" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "mantis_detect.sc" );
	script_mandatory_keys( "mantisbt/detected" );
	script_require_ports( "Services/www", 80 );
	script_tag( name: "solution_type", value: "VendorFix" );
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
if(version_in_range( version: manVer, test_version: "1.2.12", test_version2: "1.2.14" )){
	report = report_fixed_ver( installed_version: manVer, fixed_version: "1.2.15" );
	security_message( port: manPort, data: report );
	exit( 0 );
}
exit( 99 );

