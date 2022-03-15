CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103937" );
	script_cve_id( "CVE-2011-5000", "CVE-2010-4755" );
	script_version( "2021-06-07T05:38:52+0000" );
	script_name( "OpenSSH <= 5.8 Multiple DoS Vulnerabilities" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-06-07 05:38:52 +0000 (Mon, 07 Jun 2021)" );
	script_tag( name: "creation_date", value: "2014-04-09 12:03:56 +0200 (Wed, 09 Apr 2014)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/54114" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2011/Aug/2" );
	script_tag( name: "summary", value: "OpenSSH is prone to multiple Denial of Service (DoS)
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Exploiting this issue allows remote attackers to trigger
  denial-of-service conditions due to excessive memory consumption." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for details." );
	script_tag( name: "affected", value: "OpenSSH 5.8 and prior are vulnerable." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "5.8" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

