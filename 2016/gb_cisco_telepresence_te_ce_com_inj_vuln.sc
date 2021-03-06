CPE = "cpe:/a:cisco:telepresence_mcu_mse_series_software";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.809729" );
	script_version( "2021-09-20T09:01:50+0000" );
	script_cve_id( "CVE-2016-6459" );
	script_bugtraq_id( 94075 );
	script_tag( name: "cvss_base", value: "4.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-20 09:01:50 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-29 01:34:00 +0000 (Sat, 29 Jul 2017)" );
	script_tag( name: "creation_date", value: "2016-11-21 11:42:31 +0530 (Mon, 21 Nov 2016)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Cisco TelePresence CE and TC Software Command Injection Vulnerability(cisco-sa-20161102-tp)" );
	script_tag( name: "summary", value: "The host is running Cisco TelePresence
  Endpoint and is prone to local command injection vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The vulnerability is due to incomplete input
  sanitization of some commands." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to execute local shell commands with commands injected as parameters.
  Also the attacker can retrieve full information from the device including
  private keys." );
	script_tag( name: "affected", value: "All TelePresence endpoints running following
  CE or TC software are affected:
  Cisco TelePresence CE Software 8.1.0,
  Cisco TelePresence CE Software 8.0.0,
  Cisco TelePresence TC Software 7.3.0,
  Cisco TelePresence TC Software 7.3.1,
  Cisco TelePresence TC Software 7.3.2,
  Cisco TelePresence TC Software 7.3.3,
  Cisco TelePresence TC Software 7.1.0,
  Cisco TelePresence TC Software 7.1.1,
  Cisco TelePresence TC Software 7.1.2,
  Cisco TelePresence TC Software 7.1.3,
  Cisco TelePresence TC Software 7.1.4" );
	script_tag( name: "solution", value: "Apply updates as available from vendor." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvb25010" );
	script_xref( name: "URL", value: "https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20161102-tp" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
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
ciscoVer = eregmatch( pattern: "^T[CE]([^$]+$)", string: version, icase: TRUE );
if(isnull( ciscoVer[1] )){
	exit( 0 );
}
verscat = ciscoVer[0];
vers = ciscoVer[1];
if( IsMatchRegexp( verscat, "^ce." ) ){
	if(IsMatchRegexp( vers, "^8\\.0\\.0" ) || IsMatchRegexp( vers, "^8\\.1\\.0\\." )){
		VULN = TRUE;
	}
}
else {
	if(IsMatchRegexp( verscat, "^tc." )){
		if(IsMatchRegexp( vers, "^7\\.1\\.[0-4]" ) || IsMatchRegexp( vers, "^7\\.3\\.[0-3]" )){
			VULN = TRUE;
		}
	}
}
if(VULN){
	report = report_fixed_ver( installed_version: vers, fixed_version: "See advisory" );
	security_message( port: cisport, data: report );
	exit( 0 );
}
exit( 99 );

