CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140344" );
	script_version( "2021-09-08T11:01:32+0000" );
	script_tag( name: "last_modification", value: "2021-09-08 11:01:32 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-01 14:12:47 +0700 (Fri, 01 Sep 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-14 18:06:00 +0000 (Thu, 14 Sep 2017)" );
	script_cve_id( "CVE-2017-14098" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Asterisk 'CVE-2017-14098' DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_asterisk_detect.sc" );
	script_mandatory_keys( "Asterisk-PBX/Installed" );
	script_tag( name: "summary", value: "Asterisk is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "A carefully crafted URI in a From, To or Contact header could cause
  Asterisk to crash." );
	script_tag( name: "affected", value: "Asterisk Open Source 13.15.0, 14.4.0." );
	script_tag( name: "solution", value: "Upgrade to Version 13.17.1, 14.6.1 or later." );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2017-007.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("revisions-lib.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "13.15.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "13.17.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(version_is_equal( version: version, test_version: "14.4.0" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "14.6.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 0 );

