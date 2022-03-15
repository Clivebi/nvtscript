if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.804417" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_bugtraq_id( 66299 );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:N/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-03-20 12:13:13 +0530 (Thu, 20 Mar 2014)" );
	script_name( "Array Networks vxAG/xAPV Authentication Bypass Vulnerabilities" );
	script_tag( name: "summary", value: "This host is running Array Networks vxAG/xAPV and is prone to
  authentication bypass vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a default SSH credentials and check whether it is possible to login to
  the target machine." );
	script_tag( name: "insight", value: "Multiple flaws are due to

  - The program using insecure world writable permissions for the
  '/ca/bin/monitor.sh' file.

  - The 'mfg' account has a password of 'mfg' and the 'sync' account has a
  password of 'click1', which is publicly known and documented.

  - If a remote attacker has explicit knowledge of the SSH keys they can
  potentially gain privileged access to the device." );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to gain unauthorized root
  access to affected devices and completely compromise the devices." );
	script_tag( name: "affected", value: "Array Networks vxAG 9.2.0.34 and vAPV 8.3.2.17 appliances." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of
  this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer release,
  disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125761" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
port = ssh_get_port( default: 22 );
if(!soc = open_sock_tcp( port )){
	exit( 0 );
}
user = "mfg";
pass = "mfg";
login = ssh_login( socket: soc, login: user, password: pass, priv: NULL, passphrase: NULL );
if(login == 0){
	cmd = "id";
	res = ssh_cmd( socket: soc, cmd: cmd );
	if(ereg( pattern: "uid=[0-9]+.*gid=[0-9]+", string: res )){
		report = "It was possible to login as user \"" + user + "\" with password \"" + pass + "\" and to execute the \"" + cmd + "\" command. Result:\n\n" + res;
		security_message( port: port, data: report );
		close( soc );
		exit( 0 );
	}
}
close( soc );

