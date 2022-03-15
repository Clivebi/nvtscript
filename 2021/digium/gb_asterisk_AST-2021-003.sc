CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.145418" );
	script_version( "2021-08-27T08:01:04+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 08:01:04 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2021-02-19 04:02:26 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-24 17:14:00 +0000 (Wed, 24 Feb 2021)" );
	script_cve_id( "CVE-2021-26712" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Asterisk DoS Vulnerability (AST-2021-003)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_asterisk_detect.sc" );
	script_mandatory_keys( "Asterisk-PBX/Installed" );
	script_tag( name: "summary", value: "Asterisk is prone to a denial of service vulnerability where remote
  attackers could prematurely tear down SRTP calls." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An unauthenticated remote attacker could replay SRTP packets which could
  cause an Asterisk instance configured without strict RTP validation to tear down calls prematurely." );
	script_tag( name: "affected", value: "Asterisk Open Source 13.38.1, 16.16.0, 17.9.1, 18.2.0 and 16.8-cert5." );
	script_tag( name: "solution", value: "Update to version 13.38.2, 16.16.1, 17.9.2, 18.2.1, 16.8-cert6 or later." );
	script_xref( name: "URL", value: "https://downloads.asterisk.org/pub/security/AST-2021-003.html" );
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
if(version == "13.38.1"){
	report = report_fixed_ver( installed_version: version, fixed_version: "13.38.2" );
	security_message( port: port, data: report, proto: "udp" );
	exit( 0 );
}
if(version == "16.8-cert5"){
	report = report_fixed_ver( installed_version: version, fixed_version: "16.8-cert6" );
	security_message( port: port, data: report, proto: "udp" );
	exit( 0 );
}
if(version == "16.16.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "16.16.1" );
	security_message( port: port, data: report, proto: "udp" );
	exit( 0 );
}
if(version == "17.9.1"){
	report = report_fixed_ver( installed_version: version, fixed_version: "17.9.2" );
	security_message( port: port, data: report, proto: "udp" );
	exit( 0 );
}
if(version == "18.2.0"){
	report = report_fixed_ver( installed_version: version, fixed_version: "18.2.1" );
	security_message( port: port, data: report, proto: "udp" );
	exit( 0 );
}
exit( 99 );

