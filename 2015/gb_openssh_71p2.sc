CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105512" );
	script_cve_id( "CVE-2016-0777", "CVE-2016-0778" );
	script_version( "2019-05-22T07:58:25+0000" );
	script_name( "OpenSSH Client Information Leak" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:S/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2019-05-22 07:58:25 +0000 (Wed, 22 May 2019)" );
	script_tag( name: "creation_date", value: "2016-01-14 17:31:53 +0100 (Thu, 14 Jan 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_xref( name: "URL", value: "http://www.openssh.com/txt/release-7.1p2" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Update to 7.1p2 or newer." );
	script_tag( name: "summary", value: "The OpenSSH client code between 5.4 and 7.1p1 contains experimental support for resuming SSH-connections (roaming).
  The matching server code has never been shipped, but the client code was enabled by default and could be tricked by a malicious
  server into leaking client memory to the server, including private client user keys. The authentication of the server host key prevents exploitation
  by a man-in-the-middle, so this information leak is restricted to connections to malicious or compromised servers." );
	script_tag( name: "affected", value: "OpenSSH >= 5.4 < 7.1p2" );
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
if(version_in_range( version: vers, test_version: "5.4", test_version2: "7.1p1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.1p2", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

