CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150641" );
	script_version( "2021-05-28T12:49:28+0000" );
	script_tag( name: "last_modification", value: "2021-05-28 12:49:28 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-27 14:42:43 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2003-0682", "CVE-2003-0695" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSH < 3.7.1 Security Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_tag( name: "summary", value: "All versions of OpenSSH's sshd prior to 3.7.1 contain buffer
  management errors. It is uncertain whether these errors are potentially exploitable, however, we
  prefer to see bugs fixed proactively.

  Other implementations sharing common origin may also have these issues." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "OpenSSH version prior to 3.7.1." );
	script_tag( name: "solution", value: "Update to version 3.7.1 or later." );
	script_xref( name: "URL", value: "https://www.openssh.com/txt/buffer.adv" );
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
if(version_is_less( version: vers, test_version: "3.7.1" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.7.1", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

