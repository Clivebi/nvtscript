CPE = "cpe:/a:nch:axon_virtual_pbx";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900984" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-11-26 06:39:46 +0100 (Thu, 26 Nov 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-4038" );
	script_name( "Axon Virtual PBX Multiple Cross Site Scripting Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_axon_virtual_pbx_web_detect.sc" );
	script_require_ports( "Services/www", 81 );
	script_mandatory_keys( "Axon-Virtual-PBX/www/installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37157/" );
	script_xref( name: "URL", value: "http://en.securitylab.ru/nvd/387986.php" );
	script_tag( name: "impact", value: "Successful exploitation will let the attackers execute arbitrary HTML and
  script code in the affected user's browser session." );
	script_tag( name: "affected", value: "Axon Virtual PBX version 2.10 and 2.11." );
	script_tag( name: "insight", value: "The input passed into 'onok' and 'oncancel' parameters in the logon program
  is not properly sanitised before being returned to the user." );
	script_tag( name: "solution", value: "Upgrade to Axon Virtual PBX version 2.13 or later." );
	script_tag( name: "summary", value: "This host has Axon Virtual PBX installed and is prone to Multiple XSS
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.nch.com.au/pbx/index.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE, service: "www" )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "2.10", test_version2: "2.11" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.13" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

