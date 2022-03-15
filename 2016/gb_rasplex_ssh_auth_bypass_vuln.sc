if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.807609" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_cve_id( "CVE-2016-2230" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2016-03-11 15:05:52 +0530 (Fri, 11 Mar 2016)" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_name( "Rasplex Authentication Bypass Vulnerability" );
	script_tag( name: "summary", value: "This host is installed with Rasplex device and
  is prone authentication bypass vulnerability." );
	script_tag( name: "vuldetect", value: "Check if it is possible to login into
  the remote Rasplex device." );
	script_tag( name: "insight", value: "The flaw is due to the 'root' account has a
  password of 'rasplex', which is publicly known and documented." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote
  attackers to gain unauthorized root access to affected devices and completely
  compromise the devices.." );
	script_tag( name: "affected", value: "Rasplex Devices." );
	script_tag( name: "solution", value: "Information is available about a
  configuration or deployment scenario that helps to reduce the risk of the
  vulnerability." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_xref( name: "URL", value: "http://www.kb.cert.org/vuls/id/544527" );
	script_xref( name: "URL", value: "https://github.com/RasPlex/RasPlex/issues/453" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Default Accounts" );
	script_dependencies( "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	exit( 0 );
}
if(get_kb_item( "default_credentials/disable_default_account_checks" )){
	exit( 0 );
}
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
ras_port = ssh_get_port( default: 22 );
if(!soc = open_sock_tcp( ras_port )){
	exit( 0 );
}
login = ssh_login( socket: soc, login: "root", password: "rasplex", priv: NULL, passphrase: NULL );
if(login == 0){
	cmd = ssh_cmd( socket: soc, cmd: "id" );
	if(ereg( pattern: "uid=[0-9]+.*gid=[0-9]+", string: cmd )){
		security_message( port: ras_port );
		close( soc );
		exit( 0 );
	}
}
close( soc );

