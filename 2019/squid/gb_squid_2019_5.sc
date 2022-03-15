CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142633" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-07-19 08:08:43 +0000 (Fri, 19 Jul 2019)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-24 17:37:00 +0000 (Mon, 24 Aug 2020)" );
	script_cve_id( "CVE-2019-12527" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Proxy Cache Security Update Advisory SQUID-2019:5" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to a heap overflow vulnerability due to incorrect buffer
  management when processing HTTP Authentication credentials." );
	script_tag( name: "insight", value: "This allows a malicious client to write a substantial amount of arbitrary data
  to the heap. Potentially gaining ability to execute arbitrary code.

  On systems with memory access protections this can result in the Squid process being terminated unexpectedly.
  Resulting in a denial of service for all clients using the proxy.

  This issue is limited to traffic accessing the Squid Cache Manager reports or using the FTP protocol gateway." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Squid versions 4.0.23 - 4.7." );
	script_tag( name: "solution", value: "Update to version 4.8 or later." );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2019_5.txt" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: version, test_version: "4.0.23", test_version2: "4.7" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.8" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

