if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.117193" );
	script_version( "2021-02-12T11:09:59+0000" );
	script_cve_id( "CVE-2015-7744" );
	script_tag( name: "cvss_base", value: "2.6" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-02-12 11:09:59 +0000 (Fri, 12 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-29 12:40:25 +0000 (Fri, 29 Jan 2021)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_name( "Oracle MySQL Server <= 5.5.45 / 5.6 <= 5.6.26 Security Update (cpujan2016) - Linux" );
	script_tag( name: "summary", value: "Oracle MySQL Server is prone to a vulnerability in a third party library." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "wolfSSL (formerly CyaSSL) as used in MySQL does not properly handle
  faults associated with the Chinese Remainder Theorem (CRT) process when allowing ephemeral key exchange
  without low memory optimizations on a server." );
	script_tag( name: "impact", value: "The flaw makes it easier for remote attackers to obtain private RSA
  keys by capturing TLS handshakes, aka a Lenstra attack." );
	script_tag( name: "affected", value: "Oracle MySQL Server versions 5.5.45 and prior and 5.6 through 5.6.26." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.oracle.com/security-alerts/cpujan2016.html#AppendixMSQL" );
	script_xref( name: "Advisory-ID", value: "cpujan2016" );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "Databases" );
	script_dependencies( "mysql_version.sc", "os_detection.sc" );
	script_mandatory_keys( "oracle/mysql/detected", "Host/runs_unixoide" );
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
if(version_is_less_equal( version: vers, test_version: "5.5.45" ) || version_in_range( version: vers, test_version: "5.6", test_version2: "5.6.26" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See the referenced vendor advisory", install_path: path );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

