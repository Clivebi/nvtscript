CPE = "cpe:/a:centreon:centreon";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808216" );
	script_version( "$Revision: 14181 $" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 13:59:41 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2016-06-07 16:34:51 +0530 (Tue, 07 Jun 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Centreon 'POST' Parameter File Upload Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Centreon
  and is prone to file upload vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to the POST parameter 'persistant' which serves for making a
  new service run  in the background is not properly sanitised before being used to execute commands." );
	script_tag( name: "impact", value: "Successful exploitation will allow attackers to execute arbitrary PHP code by
  uploading a malicious PHP script file." );
	script_tag( name: "affected", value: "Centreon version 2.6.1" );
	script_tag( name: "solution", value: "Upgrad to Centreon version 2.6.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/38339" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2015-5265.php" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "centreon_detect.sc" );
	script_mandatory_keys( "centreon/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!cenPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!cenVer = get_app_version( cpe: CPE, port: cenPort )){
	exit( 0 );
}
if(version_is_equal( version: cenVer, test_version: "2.6.1" )){
	report = report_fixed_ver( installed_version: cenVer, fixed_version: "2.6.2" );
	security_message( data: report, port: cenPort );
	exit( 0 );
}
exit( 0 );

