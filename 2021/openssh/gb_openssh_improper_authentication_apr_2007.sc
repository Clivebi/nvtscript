CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150635" );
	script_version( "2021-05-28T11:51:20+0000" );
	script_tag( name: "last_modification", value: "2021-05-28 11:51:20 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-27 14:42:43 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2007-2243" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSH < 4.7 Improper Authentication Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_tag( name: "summary", value: "OpenSSH, when configured to use S/KEY authentication, is prone to a remote
information disclosure weakness. The issue occurs due to the S/KEY
challenge/response system being used for valid accounts. If a remote attacker
systematically attempsauthentication against a list of usernames, he can watch
the response to determine which accounts are valid.

If 'ChallengeResponseAuthentication' is set to 'Yes', which is the default
setting, OpenSSH allows the user to login by using S/KEY in the form of
'ssh userid:skey at hostname'." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "OpenSSH version 4.6 and prior." );
	script_tag( name: "solution", value: "Update to version 4.7 or later." );
	script_xref( name: "URL", value: "https://cxsecurity.com/issue/WLB-2007040138" );
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
if(version_is_less_equal( version: vers, test_version: "4.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.7", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

