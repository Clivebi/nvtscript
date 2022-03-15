CPE = "cpe:/a:kallithea:kallithea";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.806613" );
	script_version( "$Revision: 11872 $" );
	script_cve_id( "CVE-2015-5285" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-12 13:22:41 +0200 (Fri, 12 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2015-11-06 12:57:52 +0530 (Fri, 06 Nov 2015)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Kallithea 'came_from' parameter HTTP Response Splitting Vulnerability" );
	script_tag( name: "summary", value: "The host is installed with Kallithea and
  is prone to http response splitting vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists as the application fails to
  properly sanitize user input before using it as an HTTP header value via the GET
  'came_from' parameter in the login instance." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct http response splitting attacks." );
	script_tag( name: "affected", value: "Kallithea version 0.2.9 and 0.2.2" );
	script_tag( name: "solution", value: "Upgrade to Kallithea version 0.3 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/133897" );
	script_xref( name: "URL", value: "http://www.zeroscience.mk/en/vulnerabilities/ZSL-2015-5267.php" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_kallithea_detect.sc" );
	script_mandatory_keys( "Kallithea/Installed" );
	script_require_ports( "Services/www", 5000 );
	script_xref( name: "URL", value: "https://kallithea-scm.org" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!kalPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!kalVer = get_app_version( cpe: CPE, port: kalPort )){
	exit( 0 );
}
if(version_is_equal( version: kalVer, test_version: "0.2.9" ) || version_is_equal( version: kalVer, test_version: "0.2.2" )){
	report = "Installed Version: " + kalVer + "\nFixed Version: 0.3\n";
	security_message( port: kalPort, data: report );
	exit( 0 );
}

