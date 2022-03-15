CPE = "cpe:/a:cisco:telepresence_mcu_mse_series_software";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811084" );
	script_version( "2021-09-08T14:01:33+0000" );
	script_cve_id( "CVE-2017-6648" );
	script_bugtraq_id( 98934 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-09-08 14:01:33 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2017-06-08 17:37:26 +0530 (Thu, 08 Jun 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco TelePresence CE and TC Software 'SIP' DoS Vulnerability (cisco-sa-20170607-tele)" );
	script_tag( name: "summary", value: "The host is running Cisco TelePresence
  Endpoint and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The flaw is due to a lack of flow-control
  mechanisms within the software." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated, remote attacker to cause a TelePresence endpoint to reload
  unexpectedly, resulting in a denial of service (DoS) condition." );
	script_tag( name: "affected", value: "Cisco TC and CE platforms when running
  software versions prior to TC 7.3.8 and CE 8.3.0. This vulnerability affects
  the following Cisco TelePresence products,
  TelePresence MX Series,
  TelePresence SX Series,
  TelePresence Integrator C Series,
  TelePresence System EX Series,
  TelePresence DX Series,
  TelePresence System Profile MXP Series,
  TelePresence Profile Series." );
	script_tag( name: "solution", value: "Upgrade to Cisco TelePresence TC 7.3.8 or
  Cisco TelePresence CE 8.3.0 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCux94002" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170607-tele" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "CISCO" );
	script_dependencies( "gb_cisco_telepresence_detect_snmp.sc", "gb_cisco_telepresence_detect_ftp.sc" );
	script_mandatory_keys( "cisco/telepresence/version" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!cisport = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: cisport )){
	exit( 0 );
}
if(!typ = get_kb_item( "cisco/telepresence/typ" )){
	exit( 0 );
}
if(!IsMatchRegexp( typ, "MX(2|3|7|8)00$" ) && !IsMatchRegexp( typ, "G2$" ) && !IsMatchRegexp( typ, " (42|52)/55$" ) && !IsMatchRegexp( typ, " (42|52)/55( Dual$)" ) && !IsMatchRegexp( typ, "SX(1|2|8)0$" ) && !IsMatchRegexp( typ, "SpeakerTrack$" ) && !IsMatchRegexp( typ, "DX(65|7|8)0$" ) && !IsMatchRegexp( typ, "MXP" ) && !IsMatchRegexp( typ, "EX(6|9)0$" ) && !IsMatchRegexp( typ, "C(9|6|4|2)0" )){
	exit( 0 );
}
ciscoVer = eregmatch( pattern: "^T[CE]([^$]+$)", string: version, icase: TRUE );
if(isnull( ciscoVer[1] )){
	exit( 0 );
}
verscat = ciscoVer[0];
vers = ciscoVer[1];
if( IsMatchRegexp( verscat, "^ce." ) ){
	if(IsMatchRegexp( vers, "^8\\.2\\.0" ) || IsMatchRegexp( vers, "^8\\.2\\.1" ) || IsMatchRegexp( vers, "^8\\.2\\.2" )){
		fix = "8.3.0";
	}
}
else {
	if(IsMatchRegexp( verscat, "^tc." )){
		if(IsMatchRegexp( vers, "^3\\.1\\.[0|5]" ) || IsMatchRegexp( vers, "^4\\.2\\.[0-4]" ) || IsMatchRegexp( vers, "^5\\.0\\.(0|2)" ) || IsMatchRegexp( vers, "^5\\.1\\.(0|[3-7]|11|13)" ) || IsMatchRegexp( vers, "^6\\.0\\.[1-4]" ) || IsMatchRegexp( vers, "^6\\.1\\.[0-4]" ) || IsMatchRegexp( vers, "^4\\.1\\.[0-2]" ) || IsMatchRegexp( vers, "^7\\.2\\.(0|1)" ) || IsMatchRegexp( vers, "^6\\.3\\.[0-5]" ) || IsMatchRegexp( vers, "^7\\.3\\.([0-3]|[6-7])" ) || IsMatchRegexp( vers, "^7\\.1\\.[0-4]" )){
			fix = "7.3.8";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: cisport, data: report );
	exit( 0 );
}

