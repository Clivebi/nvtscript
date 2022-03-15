CPE = "cpe:/a:splunk:splunk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.805772" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-7604" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-10-30 10:45:47 +0530 (Fri, 30 Oct 2015)" );
	script_name( "Splunk Enterprise Cross-Site Scripting Vulnerability -Oct15" );
	script_tag( name: "summary", value: "The host is installed with Splunk and is
  prone to cross-site scripting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Flaw is due to improper validation of
  user-supplied input passed via unspecified vectors before being returned
  to the user." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attacker to execute arbitrary script code in a user's browser session within
  the trust relationship between their browser and the server." );
	script_tag( name: "affected", value: "Splunk Enterprise version 6.2.x before 6.2.6" );
	script_tag( name: "solution", value: "Upgrade to Splunk Enterprise version
  6.2.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.splunk.com/view/SP-CAAAPAM" );
	script_xref( name: "URL", value: "http://www.securitytracker.com/id/1033655" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_splunk_detect.sc" );
	script_mandatory_keys( "Splunk/installed" );
	script_require_ports( "Services/www", 8000 );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!http_port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!SplunkVer = get_app_version( cpe: CPE, port: http_port )){
	exit( 0 );
}
if(version_in_range( version: SplunkVer, test_version: "6.2.0", test_version2: "6.2.5" )){
	report = "Installed version: " + SplunkVer + "\n" + "Fixed version:     6.2.6" + "\n";
	security_message( port: http_port, data: report );
	exit( 0 );
}
exit( 99 );

