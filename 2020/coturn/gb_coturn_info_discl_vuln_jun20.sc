CPE = "cpe:/a:coturn:coturn";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.144195" );
	script_version( "2021-07-06T11:00:47+0000" );
	script_tag( name: "last_modification", value: "2021-07-06 11:00:47 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "creation_date", value: "2020-07-01 06:19:25 +0000 (Wed, 01 Jul 2020)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-08-18 15:05:00 +0000 (Tue, 18 Aug 2020)" );
	script_cve_id( "CVE-2020-4067" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "coturn < 4.5.1.3 Information Disclosure Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_coturn_http_detect.sc" );
	script_mandatory_keys( "coturn/detected" );
	script_tag( name: "summary", value: "coturn is prone to an information disclosure vulnerability." );
	script_tag( name: "insight", value: "In coturn there is an issue whereby STUN/TURN response buffer is not
  initialized properly. There is a leak of information between different client connections. One client (an
  attacker) could use their connection to intelligently query coturn to get interesting bytes in the padding
  bytes from the connection of another client." );
	script_tag( name: "affected", value: "coturn prior to version 4.5.1.3." );
	script_tag( name: "solution", value: "Update to version 4.5.1.3 or later." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_xref( name: "URL", value: "https://github.com/coturn/coturn/security/advisories/GHSA-c8r8-8vp5-6gcm" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "4.5.1.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "4.5.1.3" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

