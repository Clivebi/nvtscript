CPE = "cpe:/a:nagios:nagiosxi";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100811" );
	script_version( "2020-04-24T07:24:50+0000" );
	script_tag( name: "last_modification", value: "2020-04-24 07:24:50 +0000 (Fri, 24 Apr 2020)" );
	script_tag( name: "creation_date", value: "2010-09-20 15:31:27 +0200 (Mon, 20 Sep 2010)" );
	script_bugtraq_id( 43294 );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:N/I:P/A:N" );
	script_name( "Nagios XI 'users.php' Multiple Cross-Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/43294" );
	script_xref( name: "URL", value: "http://secunia.com/secunia_research/2010-115/" );
	script_xref( name: "URL", value: "http://assets.nagios.com/downloads/nagiosxi/CHANGES.TXT" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_nagios_XI_detect.sc" );
	script_mandatory_keys( "nagiosxi/installed" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Nagios XI is prone to multiple cross-site scripting vulnerabilities
  because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "Nagios XI 2009R1.3B is vulnerable, prior versions may also be
  affected." );
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
version = infos["version"];
location = infos["location"];
if(version_is_less_equal( version: version, test_version: "2009R1.3B" )){
	report = report_fixed_ver( installed_version: version, vulnerable_range: "Less or equal to 2009R1.3B", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

