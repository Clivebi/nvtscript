CPE = "cpe:/a:livezilla:livezilla";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800418" );
	script_version( "2019-09-07T11:55:45+0000" );
	script_tag( name: "last_modification", value: "2019-09-07 11:55:45 +0000 (Sat, 07 Sep 2019)" );
	script_tag( name: "creation_date", value: "2010-01-13 15:42:20 +0100 (Wed, 13 Jan 2010)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-4450" );
	script_name( "LiveZilla Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/37990" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2010 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_livezilla_detect.sc" );
	script_mandatory_keys( "LiveZilla/installed" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote attackers to execute arbitrary HTML
  and script code in a user's browser session in the context of an affected site." );
	script_tag( name: "affected", value: "LiveZilla Version 3.1.8.3 and prior on all running platform." );
	script_tag( name: "insight", value: "Input passed to the 'lat', 'lng', and 'zom' parameters in 'map.php' is not
  properly sanitised before being returned to the user." );
	script_tag( name: "summary", value: "The host is running LiveZilla and is prone to Cross-Site Scripting
  Vulnerabilities." );
	script_tag( name: "solution", value: "Apply the patch from the referenced advisory." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/508613/100/0/threaded" );
	exit( 0 );
}
require("http_func.inc.sc");
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less_equal( version: vers, test_version: "3.1.8.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

