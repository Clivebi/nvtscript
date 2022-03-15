if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108257" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2017-13077", "CVE-2017-13078", "CVE-2017-13079", "CVE-2017-13080", "CVE-2017-13081", "CVE-2017-13082", "CVE-2017-13084", "CVE-2017-13086", "CVE-2017-13087", "CVE-2017-13088" );
	script_bugtraq_id( 101274 );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-10-19 10:31:00 +0200 (Thu, 19 Oct 2017)" );
	script_name( "Ubiquiti Networks UAP/USW Products WPA2 Key Reinstallation Vulnerabilities - KRACK" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_ubnt_discovery_protocol_detect.sc" );
	script_mandatory_keys( "ubnt_discovery_proto/detected", "ubnt_discovery_proto/firmware", "ubnt_discovery_proto/short_model" );
	script_xref( name: "URL", value: "https://community.ubnt.com/t5/UniFi-Updates-Blog/FIRMWARE-3-9-3-7537-for-UAP-USW-has-been-released/ba-p/2099365" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/101274" );
	script_xref( name: "URL", value: "https://www.krackattacks.com/" );
	script_tag( name: "summary", value: "WPA2 as used in Ubiquiti Networks UAP/USW products is prone to
  multiple security weaknesses aka Key Reinstallation Attacks (KRACK)." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "impact", value: "Exploiting these issues may allow an unauthorized
  user to intercept and manipulate data or disclose sensitive information.
  This may aid in further attacks." );
	script_tag( name: "affected", value: "UAP/USW products with firmware versions below 3.9.3.7537." );
	script_tag( name: "solution", value: "Upgrade the firmware to 3.9.3.7537 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
fw = get_kb_item( "ubnt_discovery_proto/firmware" );
if(!fw || !IsMatchRegexp( fw, "^(BZ|US)" )){
	exit( 0 );
}
sm = get_kb_item( "ubnt_discovery_proto/short_model" );
if(!sm || !IsMatchRegexp( sm, "^(U7PG2|U7HD|BZ2|U2Sv2|U2IW|U7P|U2HSR|US24P250|US24PL2|USXG)" )){
	exit( 0 );
}
vers = eregmatch( pattern: "\\.v([0-9]\\.[0-9]\\.[0-9]+\\.[0-9]+)", string: fw );
if(isnull( vers[1] )){
	exit( 0 );
}
if(!IsMatchRegexp( vers[1], "^3\\.9" )){
	exit( 99 );
}
if(version_is_less( version: vers[1], test_version: "3.9.3.7537" )){
	report = report_fixed_ver( installed_version: vers[1], fixed_version: "3.9.3.7537" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

