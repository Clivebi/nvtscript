CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150648" );
	script_version( "2021-05-28T11:51:20+0000" );
	script_tag( name: "last_modification", value: "2021-05-28 11:51:20 +0000 (Fri, 28 May 2021)" );
	script_tag( name: "creation_date", value: "2021-05-27 14:42:43 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "cvss_base", value: "1.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2008-3259" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSH < 5.1 Exposure of Sensitive Information to an Unauthorized Actor Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_tag( name: "summary", value: "OpenBSD OpenSSH is prone to hijack the X11 forwarding port vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "OpenSSH versions before 5.1." );
	script_tag( name: "solution", value: "Update to version 5.1 or later." );
	script_xref( name: "URL", value: "https://www.openssh.com/txt/release-5.1" );
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
if(version_is_less( version: vers, test_version: "5.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "5.1", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

