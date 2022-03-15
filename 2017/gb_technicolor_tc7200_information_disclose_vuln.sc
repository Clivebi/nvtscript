CPE = "cpe:/o:technicolor:tc7200_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.811656" );
	script_version( "2021-09-08T13:01:42+0000" );
	script_cve_id( "CVE-2014-1677" );
	script_bugtraq_id( 65774 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-09-08 13:01:42 +0000 (Wed, 08 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-09 19:42:00 +0000 (Tue, 09 Oct 2018)" );
	script_tag( name: "creation_date", value: "2017-09-08 17:01:34 +0530 (Fri, 08 Sep 2017)" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_name( "Technicolor TC7200 Information Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is running Technicolor TC7200
  and is prone to information disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The web interface does not use cookies at all
  and does not check the IP address of the client. If admin login is successful,
  every user from the LAN can access the management interface." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers
  to obtain sensitive information." );
	script_tag( name: "affected", value: "Technicolor TC7200 with firmware
  STD6.01.12." );
	script_tag( name: "solution", value: "Update the TC7200 firmware to STD6.02 or above" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/31894/" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/538955/100/0/threaded" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_technicolor_tc7200_snmp_detect.sc" );
	script_mandatory_keys( "technicolor/detected" );
	script_require_udp_ports( "Services/udp/snmp", 161 );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!tecPort = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: tecPort )){
	exit( 0 );
}
if(vers == "STD6.01.12"){
	report = report_fixed_ver( installed_version: vers, fixed_version: "STD6.02" );
	security_message( port: tecPort, data: report, proto: "udp" );
	exit( 0 );
}
exit( 0 );

