CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103064" );
	script_version( "2019-05-22T07:58:25+0000" );
	script_tag( name: "last_modification", value: "2019-05-22 07:58:25 +0000 (Wed, 22 May 2019)" );
	script_tag( name: "creation_date", value: "2011-02-07 12:50:03 +0100 (Mon, 07 Feb 2011)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2011-0539" );
	script_bugtraq_id( 46155 );
	script_name( "OpenSSH Legacy Certificate Signing Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_xref( name: "URL", value: "https://www.securityfocus.com/bid/46155" );
	script_xref( name: "URL", value: "http://www.openssh.com/txt/release-5.8" );
	script_tag( name: "impact", value: "Successful exploits will allow attackers to gain access to sensitive
  information. This may lead to further attacks." );
	script_tag( name: "affected", value: "Versions 5.6 and 5.7 of OpenSSH are vulnerable." );
	script_tag( name: "vuldetect", value: "The SSH banner is analysed for presence of openssh and the version
  information is then taken from that banner." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "Checks whether OpenSSH is prone to an information-disclosure vulnerability." );
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
if(version_in_range( version: vers, test_version: "5.6", test_version2: "5.7" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.8", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

