CPE = "cpe:/a:dell:sonicwall_totalsecure_tz_100_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106570" );
	script_version( "2020-11-25T09:16:10+0000" );
	script_cve_id( "CVE-2015-7770" );
	script_tag( name: "last_modification", value: "2020-11-25 09:16:10 +0000 (Wed, 25 Nov 2020)" );
	script_tag( name: "creation_date", value: "2017-02-06 14:03:54 +0700 (Mon, 06 Feb 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Dell SonicWALL TZ 100 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_dell_sonicwall_tz_snmp_detect.sc" );
	script_mandatory_keys( "sonicwall/tz/detected" );
	script_tag( name: "summary", value: "Dell SonicWALL TZ 100 is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Dell SonicWall TotalSecure TZ 100 devices allow remote attackers to cause a
  denial of service via a crafted packet." );
	script_tag( name: "affected", value: "Dell SonicWALL TZ 100 devices with firmware before 5.9.1.0-22o." );
	script_tag( name: "solution", value: "Update to firmware version 5.9.1.0-22o or later." );
	script_xref( name: "URL", value: "https://jvn.jp/en/jp/JVN90135579/index.html" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!version = get_app_version( cpe: CPE )){
	exit( 0 );
}
check_vers = ereg_replace( string: version, pattern: "-", replace: "." );
if(version_is_less( version: check_vers, test_version: "5.9.1.0.22o" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "5.9.1.0-22o" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 0 );

