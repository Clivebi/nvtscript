CPE = "cpe:/a:memcached:memcached";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106981" );
	script_version( "2021-09-17T10:01:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 10:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-07-24 15:46:47 +0700 (Mon, 24 Jul 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2017-9951" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Memcached < 1.4.39 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_memcached_detect.sc", "gb_memcached_detect_udp.sc" );
	script_mandatory_keys( "memcached/detected" );
	script_tag( name: "summary", value: "Memcached is prone to a denial of service (DoS) vulnerability." );
	script_tag( name: "insight", value: "The try_read_command function in memcached.c in memcached allows
  remote attackers to cause a denial of service (segmentation fault) via a request to add/set a key,
  which makes a comparison between signed and unsigned int and triggers a heap-based buffer
  over-read." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Memcached version prior to 1.4.39." );
	script_tag( name: "solution", value: "Update to version 1.4.39 or later." );
	script_xref( name: "URL", value: "https://github.com/memcached/memcached/wiki/ReleaseNotes1439" );
	script_xref( name: "URL", value: "https://www.twistlock.com/2017/07/13/cve-2017-9951-heap-overflow-memcached-server-1-4-38-twistlock-vulnerability-report/" );
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
if(version_is_less( version: version, test_version: "1.4.39" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.4.39" );
	security_message( port: port, proto: proto, data: report );
	exit( 0 );
}
exit( 99 );

