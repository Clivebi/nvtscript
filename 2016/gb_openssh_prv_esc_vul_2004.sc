CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107069" );
	script_version( "2019-05-22T07:58:25+0000" );
	script_cve_id( "CVE-2004-1653" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-05-22 07:58:25 +0000 (Wed, 22 May 2019)" );
	script_tag( name: "creation_date", value: "2016-10-25 11:19:11 +0530 (Tue, 25 Oct 2016)" );
	script_name( "OpenBSD OpenSSH 3.9 Port Bounce Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_tag( name: "summary", value: "This host is running OpenSSH and is prone
  to privilege escalation." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to default configuration for OpenSSH which enables AllowTcpForwarding." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote authenticated users to perform a port bounce,
  when configured with an anonymous access program such as AnonCVS." );
	script_tag( name: "affected", value: "OpenSSH 3.9 and previous versions." );
	script_tag( name: "solution", value: "Upgrade to the latest version of OpenSSH." );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
vers = infos["version"];
path = infos["location"];
if(version_is_less_equal( version: vers, test_version: "3.9" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See references", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

