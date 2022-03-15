CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144458" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-08-25 04:17:06 +0000 (Tue, 25 Aug 2020)" );
	script_tag( name: "cvss_base", value: "7.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-03-17 15:39:00 +0000 (Wed, 17 Mar 2021)" );
	script_cve_id( "CVE-2020-24606" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Proxy Cache Security Update Advisory SQUID-2020:9" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is prone to a denial of service vulnerability when processing Cache
  Digest responses." );
	script_tag( name: "insight", value: "Due to Improper Input Validation Squid is vulnerable to a denial of service
  attack against the machine operating Squid." );
	script_tag( name: "impact", value: "This problem allows a trusted peer to perform a Denial of Service by
  consuming all available CPU cycles on the machine running Squid when handling a crafted Cache Digest response
  message.

  This attack is limited to Squid using cache_peer with cache digests feature." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Squid versions 3.0 - 4.12 and 5.0.1 - 5.0.3." );
	script_tag( name: "solution", value: "Update to version 4.13, 5.0.4 or later." );
	script_xref( name: "URL", value: "https://github.com/squid-cache/squid/security/advisories/GHSA-vvj7-xjgq-g2jg" );
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
if(version_in_range( version: version, test_version: "3.0", test_version2: "4.12" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.13" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_in_range( version: version, test_version: "5.0.1", test_version2: "5.0.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.0.4" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

