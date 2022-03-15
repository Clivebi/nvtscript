CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150636" );
	script_version( "2021-05-28T12:49:28+0000" );
	script_tag( name: "last_modification", value: "2021-05-28 12:49:28 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-27 14:42:43 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2006-0225" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSH <= 4.2p1 Security Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_tag( name: "summary", value: "When performing local-to-local copying functions, scp expands
  shell characters in the filename twice before making a system() call. A filename that contains
  specially crafted characters may cause arbitrary commands to be executed.

  If scp is used to transfer untrusted files or directories, a local user may be able to cause
  arbitrary code to be executed with the privileges of the process running scp." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "OpenSSH version 4.2p1 and prior." );
	script_tag( name: "solution", value: "Update to version 4.3 or later." );
	script_xref( name: "URL", value: "https://securitytracker.com/id?1015540" );
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
if(version_is_less( version: vers, test_version: "4.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "4.3", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

