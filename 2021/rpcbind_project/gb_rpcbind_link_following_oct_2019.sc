CPE = "cpe:/a:rpcbind_project:rpcbind";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150661" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-06-11 11:40:15 +0000 (Fri, 11 Jun 2021)" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-11-05 20:41:00 +0000 (Tue, 05 Nov 2019)" );
	script_cve_id( "CVE-2010-2064", "CVE-2010-2061" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "RPCBind 0.2.0 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_rpcbind_ssh_login_detect.sc" );
	script_mandatory_keys( "rpcbind/detected" );
	script_tag( name: "summary", value: "RPCBind is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Please see the references for more information on the vulnerabilities." );
	script_tag( name: "affected", value: "RPCBind version 0.2.0." );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_xref( name: "URL", value: "https://www.openwall.com/lists/oss-security/2010/06/08/3" );
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
if(version_is_equal( version: vers, test_version: "0.2.0" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See reference", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

