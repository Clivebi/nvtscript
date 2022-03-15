CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.141685" );
	script_version( "2021-07-01T11:00:40+0000" );
	script_tag( name: "last_modification", value: "2021-07-01 11:00:40 +0000 (Thu, 01 Jul 2021)" );
	script_tag( name: "creation_date", value: "2018-11-15 08:43:23 +0700 (Thu, 15 Nov 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-30 00:35:00 +0000 (Sun, 30 Dec 2018)" );
	script_cve_id( "CVE-2018-19278" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Asterisk DoS Vulnerability (AST-2018-010)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_asterisk_detect.sc" );
	script_mandatory_keys( "Asterisk-PBX/Installed" );
	script_tag( name: "summary", value: "Buffer overflow in DNS SRV and NAPTR lookups in Digium Asterisk allows remote
attackers to crash Asterisk via a specially crafted DNS SRV or NAPTR response, because a buffer size is supposed
to match an expanded length but actually matches a compressed length." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "Asterisk Open Source 15.x and 16.x." );
	script_tag( name: "solution", value: "Upgrade to Version 15.6.2, 16.0.1 or
later." );
	script_xref( name: "URL", value: "https://downloads.asterisk.org/pub/security/AST-2018-010.html" );
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
if(IsMatchRegexp( version, "^15\\." )){
	if(version_is_less( version: version, test_version: "15.6.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "15.6.2" );
		security_message( port: port, data: report, proto: "udp" );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^16\\." )){
	if(version_is_less( version: version, test_version: "16.0.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "16.0.1" );
		security_message( port: port, data: report, proto: "udp" );
		exit( 0 );
	}
}
exit( 0 );

