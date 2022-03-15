CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106822" );
	script_version( "2021-09-17T09:09:50+0000" );
	script_tag( name: "last_modification", value: "2021-09-17 09:09:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-05-23 10:00:40 +0700 (Tue, 23 May 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-11-05 01:29:00 +0000 (Sun, 05 Nov 2017)" );
	script_cve_id( "CVE-2017-9372", "CVE-2017-9359", "CVE-2017-9358" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Asterisk Multiple DoS Vulnerabilities (May 2017)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_asterisk_detect.sc" );
	script_mandatory_keys( "Asterisk-PBX/Installed" );
	script_tag( name: "summary", value: "Asterisk is prone to multiple denial of service (DoS)
  vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Asterisk is prone to multiple vulnerabilities:

  - Buffer Overrun in PJSIP transaction layer (AST-2017-002)

  - Crash in PJSIP multi-part body parser (AST-2017-003)

  - Memory exhaustion on short SCCP packets (AST-2017-004)" );
	script_tag( name: "impact", value: "An unauthenticated remote attacker may cause a denial of service." );
	script_tag( name: "affected", value: "Asterisk Open Source 11.x, 13.x, 14.x and Certified Asterisk 13.13." );
	script_tag( name: "solution", value: "Update to version 13.15.1, 14.4.1, 13.13-cert4 or later." );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2017-002.html" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2017-003.html" );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2017-004.html" );
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
if(IsMatchRegexp( version, "^11\\." ) || IsMatchRegexp( version, "^13\\." )){
	if( IsMatchRegexp( version, "^13\\.13cert" ) ){
		if(revcomp( a: version, b: "13.13cert4" ) < 0){
			report = report_fixed_ver( installed_version: version, fixed_version: "13.13-cert4" );
			security_message( port: port, data: report, proto: "udp" );
			exit( 0 );
		}
	}
	else {
		if(version_is_less( version: version, test_version: "13.15.1" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "13.15.1" );
			security_message( port: port, data: report, proto: "udp" );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( version, "^14\\." )){
	if(version_is_less( version: version, test_version: "14.4.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "14.4.1" );
		security_message( port: port, data: report, proto: "udp" );
		exit( 0 );
	}
}
exit( 99 );

