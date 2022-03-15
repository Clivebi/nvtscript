CPE = "cpe:/a:cisco:telepresence_mcu_mse_series_software";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811051" );
	script_version( "2021-09-16T13:01:47+0000" );
	script_cve_id( "CVE-2017-3825" );
	script_bugtraq_id( 98293 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-16 13:01:47 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-11 01:33:00 +0000 (Tue, 11 Jul 2017)" );
	script_tag( name: "creation_date", value: "2017-05-23 12:24:36 +0530 (Tue, 23 May 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco TelePresence CE and TC Software ICMP DoS Vulnerability (cisco-sa-20170503-ctp)" );
	script_tag( name: "summary", value: "The host is running Cisco TelePresence
  Endpoint and is prone to denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to incomplete
  input validation for the size of a received ICMP packet." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unauthenticated, remote attacker to cause the TelePresence endpoint to
  reload unexpectedly, resulting in a denial of service (DoS) condition." );
	script_tag( name: "affected", value: "Cisco TelePresence products when running
  software release CE8.1.0, CE8.0.0, CE8.1.1, CE8.2.0, CE8.2.1, CE8.2.2,
  CE 8.3.0, or CE8.3.1. Also TC4.2 through TC4.2.4, TC5.1.11, TC5.1.13,
  TC6.0.2 through TC6.0.4, TC6.1.3, TC6.1.4, TC6.3.1 through TC6.3.5, TC7.3.6,
  TC7.3.7, TC7.1.1 through TC7.1.4 are affected. This vulnerability affects the
  following Cisco TelePresence products,
  Spark Room OS,
  TelePresence DX Series,
  TelePresence MX Series,
  TelePresence SX Quick Set Series, and
  TelePresence SX Series." );
	script_tag( name: "solution", value: "Upgrade to Cisco TelePresence Collaboration
  Endpoint (CE) Software release 8.3.2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb95396" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20170503-ctp" );
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
if(!IsMatchRegexp( typ, "MX(2|3|7|8)00$" ) && !IsMatchRegexp( typ, "G2$" ) && !IsMatchRegexp( typ, " (42|52)/55$" ) && !IsMatchRegexp( typ, " (42|52)/55( Dual$)" ) && !IsMatchRegexp( typ, "SX(1|2|8)0$" ) && !IsMatchRegexp( typ, "SpeakerTrack$" ) && !IsMatchRegexp( typ, "DX(65|7|8)0$" )){
	exit( 0 );
}
ciscoVer = eregmatch( pattern: "^T[CE]([^$]+$)", string: version, icase: TRUE );
if(isnull( ciscoVer[1] )){
	exit( 0 );
}
verscat = ciscoVer[0];
vers = ciscoVer[1];
if( IsMatchRegexp( verscat, "^ce." ) ){
	if(IsMatchRegexp( vers, "^8\\.0\\.0" ) || IsMatchRegexp( vers, "^8\\.1\\.0" ) || IsMatchRegexp( vers, "^8\\.1\\.1" ) || IsMatchRegexp( vers, "^8\\.2\\.0" ) || IsMatchRegexp( vers, "^8\\.2\\.1" ) || IsMatchRegexp( vers, "^8\\.2\\.2" ) || IsMatchRegexp( vers, "^8\\.3\\.0" ) || IsMatchRegexp( vers, "^8\\.3\\.1" )){
		fix = "8.3.2";
	}
}
else {
	if(IsMatchRegexp( verscat, "^tc." )){
		if(IsMatchRegexp( vers, "^4\\.2\\.[0-4]" ) || IsMatchRegexp( vers, "^5\\.1\\.(11|13)" ) || IsMatchRegexp( vers, "^6\\.0\\.[2-4]" ) || IsMatchRegexp( vers, "^6\\.1\\.[3-4]" ) || IsMatchRegexp( vers, "^6\\.3\\.[1-5]" ) || IsMatchRegexp( vers, "^7\\.3\\.[6-7]" ) || IsMatchRegexp( vers, "^7\\.1\\.[1-4]" )){
			fix = "Apply patch from vendor or upgrade to CE8.3.2";
		}
	}
}
if(fix){
	report = report_fixed_ver( installed_version: vers, fixed_version: fix );
	security_message( port: cisport, data: report );
	exit( 0 );
}

