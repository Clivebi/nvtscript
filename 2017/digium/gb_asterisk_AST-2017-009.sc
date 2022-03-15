CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140493" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-11-09 10:24:49 +0700 (Thu, 09 Nov 2017)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Asterisk pjproject Header DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_asterisk_detect.sc" );
	script_mandatory_keys( "Asterisk-PBX/Installed" );
	script_tag( name: "summary", value: "Asterisk is prone to a buffer overflow vulnerability which leads to a
  denial of service." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "By carefully crafting invalid values in the Cseq and the Via header port,
  pjproject's packet parsing code can create strings larger than the buffer allocated to hold them. This will
  usually cause Asterisk to crash immediately. The packets do not have to be authenticated." );
	script_tag( name: "impact", value: "An unauthenticated remote attacker may crash Asterisk leading to a
  denial of service condition." );
	script_tag( name: "affected", value: "Asterisk Open Source 13.x, 14.x, 15.x and Certified Asterisk 13.13." );
	script_tag( name: "solution", value: "Upgrade to Version 13.18.1, 14.7.1, 15.1.1, 13.13-cert7 or later." );
	script_xref( name: "URL", value: "http://downloads.asterisk.org/pub/security/AST-2017-009.html" );
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
if(IsMatchRegexp( version, "^13\\." )){
	if( IsMatchRegexp( version, "^13\\.13cert" ) ){
		if(revcomp( a: version, b: "13.13cert7" ) < 0){
			report = report_fixed_ver( installed_version: version, fixed_version: "13.13-cert7" );
			security_message( port: port, data: report, proto: "udp" );
			exit( 0 );
		}
	}
	else {
		if(version_is_less( version: version, test_version: "13.18.1" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "13.18.1" );
			security_message( port: port, data: report, proto: "udp" );
			exit( 0 );
		}
	}
}
if(IsMatchRegexp( version, "^14\\." )){
	if(version_is_less( version: version, test_version: "14.7.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "14.7.1" );
		security_message( port: port, data: report, proto: "udp" );
		exit( 0 );
	}
}
if(IsMatchRegexp( version, "^15\\." )){
	if(version_is_less( version: version, test_version: "15.1.1" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "15.1.1" );
		security_message( port: port, data: report, proto: "udp" );
		exit( 0 );
	}
}
exit( 0 );

