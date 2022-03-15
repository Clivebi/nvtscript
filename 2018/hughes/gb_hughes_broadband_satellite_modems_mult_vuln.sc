CPE = "cpe:/a:hughes:broadband_satelite_modem";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.813749" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2016-9497", "CVE-2016-9496", "CVE-2016-9494", "CVE-2016-9495" );
	script_tag( name: "cvss_base", value: "8.3" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-09 23:20:00 +0000 (Wed, 09 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-08-08 14:01:09 +0530 (Wed, 08 Aug 2018)" );
	script_name( "Hughes Broadband Satellite Modems Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "The host is running Hughes Broadband
  Satellite Modem and is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a telnet connection request and check
  whether it is possible to access device without credentials." );
	script_tag( name: "insight", value: "Multiple flaws exist due to:

  - An error in the device's advanced status web page that is linked to from
    the basic status web page does not appear to properly parse malformed GET
    requests.

  - Use of Hard-coded Credentials.

  - Missing Authentication for Critical Function.

  - An Alternate Path or Channel. By default, port 1953 is accessible via telnet
    and does not require authentication." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to conduct a denial-of-service condition, gain access to the device's
  default telnet port 23 and telnet port 1953 and cause modem to reboot." );
	script_tag( name: "affected", value: "Hughes Broadband Satellite Modem models
  HN7740S, DW7000 and HN7000S/SM. Other models may also be affected." );
	script_tag( name: "solution", value: "Upgrade Hughes Broadband Satellite Modem
  to firmware version 6.9.0.34 or higher, and configure to prevent exploit of the
  listed potential vulnerabilities. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/614751" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_hughes_broadband_satellite_modems_detect.sc" );
	script_mandatory_keys( "hughes_broadband_satelite_modem/detected" );
	script_require_ports( "Services/telnet", 1953 );
	exit( 0 );
}
require("telnet_func.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
port = telnet_get_port( default: 1953 );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
recv = recv( socket: soc, length: 4096, timeout: 10 );
if(ContainsString( recv, "Broadband Satellite" ) && ContainsString( recv, "Hughes Network Systems" ) && ContainsString( recv, "Install Console" ) && ContainsString( recv, "Main Menu" )){
	send( socket: soc, data: "\r\n" );
	recv = recv( socket: soc, length: 4096, timeout: 10 );
	close( soc );
	if(ContainsString( recv, "Display Current Configuration" ) && ContainsString( recv, "Display Satellite Interface Statistics" ) && ContainsString( recv, "Gateway Reset" ) && ContainsString( recv, "Gateway Unlicense" ) && ContainsString( recv, "Display Active Routing" )){
		report = "It was possible to gain unrestricted telnet access without entering credentials.";
		security_message( port: port, data: report );
		exit( 0 );
	}
	exit( 99 );
}
exit( 0 );

