if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.808592" );
	script_version( "2021-02-12T11:09:59+0000" );
	script_cve_id( "CVE-2016-3518", "CVE-2016-3588", "CVE-2016-5436", "CVE-2016-5437", "CVE-2016-3424", "CVE-2016-5441", "CVE-2016-5442", "CVE-2016-5443" );
	script_bugtraq_id( 91967, 91983, 91906, 91917, 91976, 91915, 91974, 91963 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-02-12 11:09:59 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2016-07-21 12:30:40 +0530 (Thu, 21 Jul 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Oracle MySQL Server 5.7 <= 5.7.12 Security Update (cpujul2016) - Windows" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to multiple unspecified vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Multiple unspecified errors exist in the 'MySQL Server' component
  via unknown vectors." );
	script_tag( name: "impact", value: "Successful exploitation will allow an authenticated remote attacker
  to affect integrity, and availability via unknown vectors." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.7 through 5.7.12." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpujul2016.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpujul2016" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_windows" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
CPE = "cpe:/a:oracle:mysql";
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(version_in_range( version: vers, test_version: "5.7", test_version2: "5.7.12" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See the referenced vendor advisory", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

