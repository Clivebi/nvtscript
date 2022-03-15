CPE = "cpe:/a:openssl:openssl";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150707" );
	script_version( "2021-08-25T12:01:03+0000" );
	script_tag( name: "last_modification", value: "2021-08-25 12:01:03 +0000 (Wed, 25 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-07-19 12:38:23 +0000 (Mon, 19 Jul 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-15 13:29:00 +0000 (Thu, 15 Oct 2020)" );
	script_cve_id( "CVE-2014-0160" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "OpenSSL Buffer Overflow Vulnerability (20140407, Heartbleed) - Linux" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Buffer overflow" );
	script_dependencies( "gb_openssl_consolidation.sc", "os_detection.sc" );
	script_mandatory_keys( "openssl/detected", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "OpenSSL is prone to a buffer overflow vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A missing bounds check in the handling of the TLS heartbeat
  extension can be used to reveal up to 64kB of memory to a connected client or server
  (a.k.a. Heartbleed)." );
	script_tag( name: "affected", value: "OpenSSL version 1.0.1 through 1.0.1f.

  This issue did not affect versions of OpenSSL prior to 1.0.1." );
	script_tag( name: "solution", value: "Update to version 1.0.1g or later." );
	script_xref( name: "URL", value: "https://www.openssl.org/news/secadv/20140407.txt" );
	script_xref( name: "URL", value: "https://heartbleed.com/" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_in_range( version: version, test_version: "1.0.1", test_version2: "1.0.1f" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.0.1g", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

