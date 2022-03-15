CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105003" );
	script_bugtraq_id( 66355 );
	script_cve_id( "CVE-2014-2532" );
	script_version( "2019-05-22T07:58:25+0000" );
	script_name( "OpenSSH 'child_set_env()' Function Security Bypass Vulnerability" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2019-05-22 07:58:25 +0000 (Wed, 22 May 2019)" );
	script_tag( name: "creation_date", value: "2014-04-09 12:39:48 +0200 (Wed, 09 Apr 2014)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2014 Greenbone Networks GmbH" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/66355" );
	script_tag( name: "impact", value: "The security bypass allows remote attackers to bypass intended environment
  restrictions by using a substring located before a wildcard character." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "sshd in OpenSSH before 6.6 does not properly support wildcards on AcceptEnv
  lines in sshd_config." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "summary", value: "OpenSSH is prone to a security-bypass vulnerability." );
	script_tag( name: "affected", value: "Versions prior to OpenSSH 6.6 are vulnerable." );
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
if(version_is_less( version: vers, test_version: "6.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.6", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

