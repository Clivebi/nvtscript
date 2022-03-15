CPE = "cpe:/a:mongodb:mongodb";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140491" );
	script_version( "2021-09-09T10:07:02+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 10:07:02 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-11-07 12:22:09 +0700 (Tue, 07 Nov 2017)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-22 21:39:00 +0000 (Wed, 22 Nov 2017)" );
	script_cve_id( "CVE-2017-15535" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "MongoDB DoS Vulnerability - Oct17 (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Databases" );
	script_dependencies( "gb_mongodb_detect.sc", "os_detection.sc" );
	script_mandatory_keys( "mongodb/installed", "Host/runs_unixoide" );
	script_tag( name: "summary", value: "MongoDB is prone to a denial of service vulnerability." );
	script_tag( name: "insight", value: "MongoDB has a disabled-by-default configuration setting,
networkMessageCompressors (aka wire protocol compression), which exposes a vulnerability when enabled that could
be exploited by a malicious attacker to deny service or modify memory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "MongoDB version 3.4.x and 3.5.x." );
	script_tag( name: "solution", value: "Update to version 3.4.10, 3.6.0-rc0 or later." );
	script_xref( name: "URL", value: "https://jira.mongodb.org/browse/SERVER-31273" );
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
if(version_in_range( version: version, test_version: "3.4.0", test_version2: "3.4.9" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.4.10" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^3\\.5\\." )){
	report = report_fixed_ver( installed_version: version, fixed_version: "3.6.0-rc0" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

