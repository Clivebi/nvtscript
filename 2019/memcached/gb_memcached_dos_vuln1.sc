CPE = "cpe:/a:memcached:memcached";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142840" );
	script_version( "2021-08-30T10:01:19+0000" );
	script_tag( name: "last_modification", value: "2021-08-30 10:01:19 +0000 (Mon, 30 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-09-03 07:14:37 +0000 (Tue, 03 Sep 2019)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-26 16:15:00 +0000 (Tue, 26 May 2020)" );
	script_cve_id( "CVE-2019-15026" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Memcached < 1.5.17 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_memcached_detect.sc", "gb_memcached_detect_udp.sc" );
	script_mandatory_keys( "memcached/detected" );
	script_tag( name: "summary", value: "Memcached is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "insight", value: "Memcached 1.5.16 has a stack-based buffer over-read in
  conn_to_str in memcached.c when UNIX sockets are used." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Memcached prior to 1.5.17." );
	script_tag( name: "solution", value: "Update to version 1.5.17 or later." );
	script_xref( name: "URL", value: "https://github.com/memcached/memcached/wiki/ReleaseNotes1517" );
	script_xref( name: "URL", value: "https://github.com/memcached/memcached/commit/554b56687a19300a75ec24184746b5512580c819" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_version_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
version = infos["version"];
proto = infos["proto"];
if(version_is_less( version: version, test_version: "1.5.17" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.5.17" );
	security_message( port: port, proto: proto, data: report );
	exit( 0 );
}
exit( 99 );

