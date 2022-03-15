CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.812050" );
	script_version( "2021-09-09T13:03:05+0000" );
	script_cve_id( "CVE-2017-15906" );
	script_bugtraq_id( 101552 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-09-09 13:03:05 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2017-10-27 13:03:59 +0530 (Fri, 27 Oct 2017)" );
	script_name( "OpenSSH 'sftp-server' Security Bypass Vulnerability (Windows)" );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_openssh_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssh/detected", "Host/runs_windows" );
	script_xref( name: "URL", value: "https://www.openssh.com/txt/release-7.6" );
	script_xref( name: "URL", value: "https://github.com/openbsd/src/commit/a6981567e8e" );
	script_tag( name: "summary", value: "This host is installed with openssh and
  is prone to security bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw exists in the 'process_open' function
  in sftp-server.c script which does not properly prevent write operations in
  readonly mode." );
	script_tag( name: "impact", value: "Successfully exploiting this issue allows
  local users to bypass certain security restrictions and perform unauthorized
  actions. This may lead to further attacks." );
	script_tag( name: "affected", value: "OpenSSH versions before 7.6 on Windows" );
	script_tag( name: "solution", value: "Upgrade to OpenSSH version 7.6 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less( version: vers, test_version: "7.6" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.6", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

