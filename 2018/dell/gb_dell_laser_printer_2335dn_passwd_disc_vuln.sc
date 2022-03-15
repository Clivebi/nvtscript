CPE = "cpe:/h:dell:2335dn";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.814218" );
	script_version( "2021-06-24T11:00:30+0000" );
	script_cve_id( "CVE-2018-15748" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:N/A:N" );
	script_tag( name: "last_modification", value: "2021-06-24 11:00:30 +0000 (Thu, 24 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "creation_date", value: "2018-09-19 16:18:38 +0530 (Wed, 19 Sep 2018)" );
	script_name( "Dell Laser MFP 2335dn Printer Password Disclosure Vulnerability" );
	script_tag( name: "summary", value: "This host is running Dell Laser MFP 2335dn
  Printer and is prone to a password disclosure vulnerability." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP GET request and checks
  if if is possible to access sensitive information." );
	script_tag( name: "insight", value: "The flaw exists as any user can retrieve the
  configured SMTP or LDAP password by viewing the HTML source code of the Email
  Settings webpage. Moreover by default printer did not have any admin credentials
  set. Also in some cases, authentication can be achieved with the blank default
  password for the admin account." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  attacker to gain access to potentially sensitive information." );
	script_tag( name: "affected", value: "Dell 2335dn printers with Printer Firmware
  Version 2.70.05.02, Engine Firmware Version 1.10.65, and Network Firmware Version
  V4.02.15(2335dn MFP) 11-22-2010. Other versions may be affected as well." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_xref( name: "URL", value: "https://www.gerrenmurphy.com/dell-2335dn-password-disclosure" );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_category( ACT_ATTACK );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dell_laser_printer_detect.sc" );
	script_mandatory_keys( "Dell/Laser/MFP/Printer/Running" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
url = "/default.html";
req = http_get_req( port: port, url: url );
res = http_keepalive_send_recv( port: port, data: req );
if(http_vuln_check( port: port, url: url, pattern: "Dell Laser MFP 2335dn", check_header: TRUE, extra_check: make_list( "var ldapPassword = \"",
	 "var smtpPassword = \"" ) )){
	report = http_report_vuln_url( port: port, url: url );
	security_message( data: report, port: port );
	exit( 0 );
}
exit( 99 );

