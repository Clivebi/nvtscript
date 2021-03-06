CPE = "cpe:/a:solarwinds:orion_network_performance_monitor";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100941" );
	script_version( "2019-06-24T11:54:34+0000" );
	script_tag( name: "last_modification", value: "2019-06-24 11:54:34 +0000 (Mon, 24 Jun 2019)" );
	script_tag( name: "creation_date", value: "2010-12-09 13:44:03 +0100 (Thu, 09 Dec 2010)" );
	script_cve_id( "CVE-2010-4828" );
	script_bugtraq_id( 45257 );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_name( "SolarWinds Orion Network Performance Monitor (NPM) Multiple Cross Site Scripting Vulnerabilities" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/45257" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "This script is Copyright (C) 2010 Greenbone Networks GmbH" );
	script_dependencies( "gb_solarwinds_orion_npm_consolidation.sc" );
	script_mandatory_keys( "solarwinds/orion/npm/detected" );
	script_tag( name: "summary", value: "SolarWinds Orion NPM is prone to multiple cross-site-scripting
  vulnerabilities because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage these issues to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may let the attacker steal
  cookie-based authentication credentials and launch other attacks." );
	script_tag( name: "affected", value: "SolarWinds Orion Network Performance Monitor (NPM) 10.1 is vulnerable,
  other versions may also be affected." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the
  disclosure of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade
  to a newer release, disable respective features, remove the product or replace the product by another one." );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_equal( version: version, test_version: "10.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "None", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

