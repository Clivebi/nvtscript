if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105398" );
	script_version( "2020-10-08T05:08:08+0000" );
	script_cve_id( "CVE-2012-1493", "CVE-2013-0137", "CVE-2013-3619", "CVE-2014-8428", "CVE-2015-0936", "CVE-2016-1561" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-10-08 05:08:08 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "creation_date", value: "2015-10-14 11:48:40 +0200 (Wed, 14 Oct 2015)" );
	script_name( "Static SSH Key Used" );
	script_category( ACT_ATTACK );
	script_family( "Gain a shell remotely" );
	script_copyright( "Copyright (C) 2015 Greenbone Networks GmbH" );
	script_dependencies( "ssh_detect.sc", "gb_default_credentials_options.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "ssh/server_banner/available" );
	script_exclude_keys( "default_credentials/disable_default_account_checks" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125761/Array-Networks-vxAG-xAPV-Privilege-Escalation.html" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2015/Jan/76" );
	script_xref( name: "URL", value: "https://github.com/cmaruti/reports/raw/master/barracuda_load_balancer_vm.pdf" );
	script_xref( name: "URL", value: "https://gist.github.com/todb-r7/5d86ecc8118f9eeecc15" );
	script_xref( name: "URL", value: "https://blog.rapid7.com/2016/04/07/r7-2016-04-exagrid-backdoor-ssh-keys-and-hardcoded-credentials/" );
	script_xref( name: "URL", value: "https://www.trustmatta.com/advisories/MATTA-2012-002.txt" );
	script_xref( name: "URL", value: "https://blog.rapid7.com/2012/06/11/scanning-for-vulnerable-f5-bigips-with-metasploit/" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125754/Loadbalancer.org-Enterprise-VA-7.5.2-Static-SSH-Key.html" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/662676" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/125755/quantum-root.txt" );
	script_xref( name: "URL", value: "https://github.com/mitchellh/vagrant/tree/master/keys" );
	script_xref( name: "URL", value: "https://blog.rapid7.com/2013/11/06/supermicro-ipmi-firmware-vulnerabilities/" );
	script_tag( name: "impact", value: "A remote attacker can exploit this issue to gain unauthorized
  access to affected devices. Successfully exploiting this issue allows attackers to completely
  compromise the devices." );
	script_tag( name: "vuldetect", value: "Try to login as a specific user using a known static SSH private key." );
	script_tag( name: "solution", value: "Remove the known SSH private key." );
	script_tag( name: "summary", value: "The remote host has a known private key installed." );
	script_tag( name: "affected", value: "The following products / devices are currently checked / known to be vulnerable:

  - Array Networks vxAG 9.2.0.34 and vAPV 8.3.2.17 appliances

  - Barracuda Load Balancer - firmware version 5.0.0.015 (CVE-2014-8428)

  - Ceragon FibeAir IP-10 (CVE-2015-0936)

  - ExaGrid storage devices running firmware prior to version 4.8 P26 (CVE-2016-1561)

  - F5 BIG-IP version 11.1.0 build 1943.0 (CVE-2012-1493)

  - Loadbalancer.org Enterprise VA 7.5.2 and below

  - Digital Alert Systems DASDEC and Monroe Electronics One-Net E189 Emergency Alert System (EAS) devices (CVE-2013-0137)

  - Quantum DXi V1000 2.2.1 and below

  - Vagrant base boxes

  - Intelligent Platform Management Interface (IPMI) with firmware for Supermicro X9 generation motherboards
  before SMT_X9_317 and firmware for Supermicro X8 generation motherboards before SMT X8 312 (CVE-2013-3619)

  Other products / devices and firmware versions might be affected as well." );
	script_tag( name: "qod_type", value: "remote_active" );
	script_tag( name: "solution_type", value: "Workaround" );
	exit( 0 );
}
require("bad_ssh_keys.inc.sc");
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
loginCheck = ssh_login( socket: soc, login: "root", password: NULL, priv: check_key, passphrase: NULL );
close( soc );
if(loginCheck == 0){
	exit( 0 );
}
for entry in bad_keys {
	es = split( buffer: entry, sep: ":split:", keep: FALSE );
	if(isnull( es[0] ) || isnull( es[1] )){
		continue;
	}
	user = es[0];
	pkey = es[1];
	if(!soc = open_sock_tcp( port )){
		exit( 0 );
	}
	login = ssh_login( socket: soc, login: user, password: NULL, priv: pkey, passphrase: NULL );
	close( soc );
	if(login == 0){
		report = "It was possible to login using username \"" + user + "\" and the following private SSH key:\n" + pkey;
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

