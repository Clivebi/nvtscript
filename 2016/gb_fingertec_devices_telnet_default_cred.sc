if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807525" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-16 15:57:40 +0530 (Wed, 16 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "FingerTec Devices Telnet Default Credentials Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with FingerTec
  device and is prone to default credentials vulnerability." );
	script_tag( name: "vuldetect", value: "Check if it is possible to do telnet
  login into the FingerTec device." );
	script_tag( name: "insight", value: "The flaw is due to default user:passwords
  which is publicly known and documented." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain unauthorized root access to affected devices and completely
  compromise the devices." );
	script_tag( name: "affected", value: "FingerTec Devices." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://blog.infobytesec.com/2014/07/perverting-embedded-devices-zksoftware_2920.html" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "telnetserver_detect_type_nd_version.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "telnet/fingertex/device/detected" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("telnet_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("dump.inc.sc");
fingport = telnet_get_port( default: 23 );
if(!banner = telnet_get_banner( port: fingport )){
	exit( 0 );
}
if(!ContainsString( banner, "ZEM" )){
	exit( 0 );
}
soc = open_sock_tcp( fingport );
if(!soc){
	exit( 0 );
}
creds = make_array( "root", "founder88", "root", "colorkey", "root", "solokey", "root", "swsbzkgn", "admin", "admin", "888", "manage", "manage", "888", "asp", "test", "888", "asp", "root", "root", "admin", "1234" );
for cred in keys( creds ) {
	recv = recv( socket: soc, length: 2048 );
	if(ContainsString( recv, "login:" )){
		send( socket: soc, data: cred + "\r\n" );
		recv = recv( socket: soc, length: 128 );
		if(ContainsString( recv, "Password:" )){
			send( socket: soc, data: creds[cred] + "\r\n" );
			recv = recv( socket: soc, length: 1024 );
			if(IsMatchRegexp( recv, "BusyBox v([0-9.]+)" )){
				report += "\\n\\n" + cred + ":" + creds[cred] + "\\n";
				security_message( port: fingport, data: report );
				close( soc );
			}
		}
	}
}
close( soc );

