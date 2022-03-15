CPE = "cpe:/a:paessler:prtg_traffic_grapher";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100216" );
	script_version( "2020-02-28T06:49:00+0000" );
	script_tag( name: "last_modification", value: "2020-02-28 06:49:00 +0000 (Fri, 28 Feb 2020)" );
	script_tag( name: "creation_date", value: "2009-06-01 13:46:24 +0200 (Mon, 01 Jun 2009)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_cve_id( "CVE-2009-1849" );
	script_bugtraq_id( 35128 );
	script_name( "PRTG Traffic Grapher 'Monitor_Bandwidth' Cross Site Scripting Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Web application abuses" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_dependencies( "prtg_traffic_grapher_detect.sc" );
	script_mandatory_keys( "prtgtrafficgrapher/detected" );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "PRTG Traffic Grapher is prone to a cross-site scripting
  vulnerability because it fails to properly sanitize user-supplied input." );
	script_tag( name: "impact", value: "An attacker may leverage this issue to execute arbitrary script code
  in the browser of an unsuspecting user in the context of the affected site. This may allow the attacker
  to steal cookie-based authentication credentials and to launch other attacks." );
	script_tag( name: "affected", value: "PRTG Traffic Grapher 6.2.2.977 is vulnerable." );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/35128" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "6.2.2.977" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

