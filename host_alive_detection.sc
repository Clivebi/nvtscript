if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.100315" );
	script_version( "2021-05-04T06:55:53+0000" );
	script_tag( name: "last_modification", value: "2021-05-04 06:55:53 +0000 (Tue, 04 May 2021)" );
	script_tag( name: "creation_date", value: "2009-10-26 10:02:32 +0100 (Mon, 26 Oct 2009)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:N" );
	script_name( "Ping Host" );
	script_category( ACT_SCANNER );
	script_family( "Port scanners" );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_add_preference( name: "Use nmap", type: "checkbox", value: "yes", id: 8 );
	script_add_preference( name: "Report about unrechable Hosts", type: "checkbox", value: "no", id: 6 );
	script_add_preference( name: "Mark unrechable Hosts as dead (not scanning)", type: "checkbox", value: "yes", id: 5 );
	script_add_preference( name: "Report about reachable Hosts", type: "checkbox", value: "no", id: 9 );
	script_add_preference( name: "Use ARP", type: "checkbox", value: "no", id: 4 );
	script_add_preference( name: "Do a TCP ping", type: "checkbox", value: "no", id: 1 );
	script_add_preference( name: "TCP ping tries also TCP-SYN ping", type: "checkbox", value: "no", id: 2 );
	script_add_preference( name: "TCP ping tries only TCP-SYN ping", type: "checkbox", value: "no", id: 7 );
	script_add_preference( name: "Do an ICMP ping", type: "checkbox", value: "yes", id: 3 );
	script_add_preference( name: "nmap additional ports for -PA", type: "entry", value: "137,587,3128,8081", id: 10 );
	script_add_preference( name: "nmap: try also with only -sP", type: "checkbox", value: "no", id: 11 );
	script_add_preference( name: "Log nmap output", type: "checkbox", value: "no", id: 12 );
	script_add_preference( name: "Log failed nmap calls", type: "checkbox", value: "no", id: 13 );
	script_add_preference( name: "nmap timing policy", type: "radio", value: "Normal;Paranoid;Sneaky;Polite;Aggressive;Insane", id: 14 );
	script_tag( name: "summary", value: "This detection determines whether a remote host is
  alive by getting a response when sending a request." );
	script_tag( name: "vuldetect", value: "Several methods can be configured for detecting
  whether a host is alive:

  - An ICMP message is sent to the host and a response is taken as alive sign.

  - An ARP request is sent and a response is taken as alive sign.

  - A number of typical TCP services are tried and their presence is taken as alive sign.

  None of the methods is failsafe. It depends on network and/or host configurations
  whether they succeed or not. Both, false positives and false negatives, can occur.
  Therefore the methods are configurable.

  If you select to consider the hosts as alive, this can cause considerable timeouts
  and therefore a long scan duration in case the hosts are in fact not available." );
	script_tag( name: "insight", value: "The detection methods might fail for the following
  reasons:

  - ICMP: This might be disabled for an environment and would then cause false negatives
  as hosts are believed to be dead that actually are alive. In contrast it is also
  possible that a Firewall between the scanner and the target host is answering to the
  ICMP message and thus hosts are believed to be alive that actually are dead.

  - TCP ping: Similar to the ICMP case a Firewall between the scanner and the target might
  answer to the sent probes and thus hosts are believed to be alive that actually are
  dead." );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
tcp_ping = script_get_preference( name: "Do a TCP ping", id: 1 );
if(isnull( tcp_ping )){
	tcp_ping = "no";
}
tcp_syn_ping = script_get_preference( name: "TCP ping tries also TCP-SYN ping", id: 2 );
if(isnull( tcp_syn_ping )){
	tcp_syn_ping = "no";
}
icmp_ping = script_get_preference( name: "Do an ICMP ping", id: 3 );
if(isnull( icmp_ping )){
	icmp_ping = "yes";
}
arp_ping = script_get_preference( name: "Use ARP", id: 4 );
if(isnull( arp_ping )){
	arp_ping = "no";
}
tcp_syn_ping_only = script_get_preference( name: "TCP ping tries only TCP-SYN ping", id: 7 );
if(isnull( tcp_syn_ping_only )){
	tcp_syn_ping_only = "no";
}
report_up = script_get_preference( name: "Report about reachable Hosts", id: 9 );
if(isnull( report_up )){
	report_up = "no";
}
mark_dead = script_get_preference( name: "Mark unrechable Hosts as dead (not scanning)", id: 5 );
if(isnull( mark_dead )){
	mark_dead = "yes";
}
test_alive_hosts_only = get_preference( "test_alive_hosts_only" );
if(test_alive_hosts_only && ContainsString( test_alive_hosts_only, "yes" )){
	if(ContainsString( report_up, "yes" )){
		used_methods = "";
		methods_count = 0;
		if(ContainsString( mark_dead, "no" )){
			log_message( port: 0, data: "Host is considered as alive, Methods used: Consider Alive via Boreas Host Alive Scanner" );
			set_kb_item( name: "/tmp/start_time", value: unixtime() );
			exit( 0 );
		}
		if(ContainsString( icmp_ping, "yes" )){
			used_methods += "ICMP";
			methods_count++;
		}
		if( ContainsString( tcp_syn_ping, "yes" ) ){
			if(methods_count){
				used_methods += ", ";
			}
			used_methods += "TCP-ACK, TCP-SYN";
			methods_count++;
		}
		else {
			if( ContainsString( tcp_syn_ping_only, "yes" ) ){
				if(methods_count){
					used_methods += ", ";
				}
				used_methods += "TCP-SYN";
				methods_count++;
			}
			else {
				if(ContainsString( tcp_ping, "yes" )){
					if(methods_count){
						used_methods += ", ";
					}
					used_methods += "TCP";
					methods_count++;
				}
			}
		}
		if(ContainsString( arp_ping, "yes" )){
			if(methods_count){
				used_methods += ", ";
			}
			used_methods += "ARP";
		}
		log_message( port: 0, data: "Host is alive, Methods used: " + used_methods + " ping via Boreas Host Alive Scanner" );
	}
	if(ContainsString( icmp_ping, "yes" )){
		set_kb_item( name: "/tmp/ping/ICMP", value: 1 );
	}
	if(ContainsString( tcp_syn_ping, "yes" ) || ContainsString( tcp_syn_ping_only, "yes" ) || ContainsString( tcp_ping, "yes" )){
		set_kb_item( name: "/tmp/ping/TCP", value: 1 );
	}
	set_kb_item( name: "/tmp/start_time", value: unixtime() );
	exit( 0 );
}
require("misc_func.inc.sc");
require("list_array_func.inc.sc");
require("host_details.inc.sc");
require("version_func.inc.sc");
require("byte_func.inc.sc");
var report_dead_methods, failed_nmap_report;
report_dead_methods = "";
failed_nmap_report = "";
func check_pa_port_list( list ){
	var list, ports, port;
	if(!list){
		return FALSE;
	}
	ports = split( buffer: list, sep: ",", keep: FALSE );
	for port in ports {
		if(!ereg( pattern: "^[0-9]{1,5}$", string: port )){
			return FALSE;
		}
		if(int( port ) > 65535){
			return FALSE;
		}
	}
	return TRUE;
}
func run_tcp_syn_ping( argv, pa_ports, targetip, pattern, report_up, log_nmap_output, log_failed_nmap ){
	var argv, pa_ports, targetip, pattern, report_up, log_nmap_output, log_failed_nmap;
	var argv_tcp_syn, res, report;
	argv_tcp_syn = argv;
	argv_tcp_syn[x++] = "-PS" + pa_ports;
	argv_tcp_syn[x++] = targetip;
	res = pread( cmd: "nmap", argv: argv_tcp_syn );
	if( res && egrep( pattern: pattern, string: res ) && !ContainsString( res, "Host seems down" ) ){
		if(ContainsString( report_up, "yes" ) || ContainsString( log_nmap_output, "yes" )){
			report = "";
			if(ContainsString( report_up, "yes" )){
				report += "Host is alive (successful TCP SYN service ping), Method: nmap";
			}
			if(ContainsString( log_nmap_output, "yes" )){
				report += "\nnmap command: " + join( list: argv_tcp_syn ) + "\n\n" + res;
				if(ContainsString( log_failed_nmap, "yes" ) && strlen( failed_nmap_report ) > 0){
					report += "\n\nFailed nmap calls / unexpected replies:" + failed_nmap_report;
				}
			}
			log_message( port: 0, data: report );
		}
		set_kb_item( name: "/tmp/ping/TCP", value: 1 );
		exit( 0 );
	}
	else {
		if( res && ContainsString( res, "Nmap done" ) && ContainsString( res, "Host seems down" ) ){
			report_dead_methods += "\n\nHost is down (failed TCP SYN service ping), Method: nmap";
			if(ContainsString( log_nmap_output, "yes" )){
				report_dead_methods += "\nnmap command: " + join( list: argv_tcp_syn ) + "\n\n" + res;
			}
		}
		else {
			failed_nmap_report += res + "\n\n";
		}
	}
}
use_nmap = script_get_preference( name: "Use nmap", id: 8 );
if(isnull( use_nmap )){
	use_nmap = "yes";
}
report_dead = script_get_preference( name: "Report about unrechable Hosts", id: 6 );
if(isnull( report_dead )){
	report_dead = "no";
}
sp_only = script_get_preference( name: "nmap: try also with only -sP", id: 11 );
if(isnull( sp_only )){
	sp_only = "no";
}
log_nmap_output = script_get_preference( name: "Log nmap output", id: 12 );
if(isnull( log_nmap_output )){
	log_nmap_output = "no";
}
log_failed_nmap = script_get_preference( name: "Log failed nmap calls", id: 13 );
if(isnull( log_failed_nmap )){
	log_failed_nmap = "no";
}
set_kb_item( name: "/ping_host/mark_dead", value: mark_dead );
set_kb_item( name: "/tmp/start_time", value: unixtime() );
if(ContainsString( icmp_ping, "no" ) && ContainsString( tcp_ping, "no" ) && ContainsString( arp_ping, "no" ) && ContainsString( sp_only, "no" )){
	log_message( port: 0, data: "The alive test was not launched because no method was selected." );
	exit( 0 );
}
if(ContainsString( mark_dead, "no" ) && ContainsString( report_dead, "no" )){
	if(ContainsString( log_nmap_output, "yes" )){
		log_message( port: 0, data: "'Log nmap output' was set to 'yes' but 'Report about unrechable Hosts' and 'Mark unrechable Hosts as dead (not scanning)' to no. Plugin will exit without logging." );
	}
	exit( 0 );
}
if(ContainsString( use_nmap, "yes" ) && !find_in_path( "nmap" )){
	log_message( port: 0, data: "Nmap was selected for host discovery but is not present on this system. Falling back to built-in discovery method." );
	use_nmap = "no";
}
targetip = get_host_ip();
ownip = this_host();
if( ContainsString( use_nmap, "yes" ) ){
	argv[x++] = "nmap";
	argv[x++] = "--reason";
	argv[x++] = "-sP";
	timing_templates = make_array( "Paranoid", 0, "Sneaky", 1, "Polite", 2, "Normal", 3, "Aggressive", 4, "Insane", 5 );
	timing_preference = script_get_preference( name: "nmap timing policy", id: 14 );
	if(isnull( timing_preference )){
		timing_preference = "Normal";
	}
	timing = timing_templates[timing_preference];
	if(!isnull( timing )){
		_timing = "-T" + timing;
		argv[x++] = _timing;
	}
	if(!ContainsString( arp_ping, "yes" )){
		argv[x++] = "--send-ip";
	}
	pattern = "Host.*(is|appears to be) up";
	if(TARGET_IS_IPV6()){
		argv[x++] = "-6";
	}
	source_iface = get_preference( "source_iface" );
	if(IsMatchRegexp( source_iface, "^[0-9a-zA-Z:_]+$" )){
		argv[x++] = "-e";
		argv[x++] = source_iface;
	}
	if(ContainsString( sp_only, "yes" )){
		argv_sp_only = argv;
		argv_sp_only[x++] = targetip;
		res = pread( cmd: "nmap", argv: argv_sp_only );
		if( res && egrep( pattern: pattern, string: res ) && !ContainsString( res, "Host seems down" ) ){
			if(ContainsString( report_up, "yes" ) || ContainsString( log_nmap_output, "yes" )){
				report = "";
				if( ContainsString( res, "received arp-response" ) ) {
					reason = "ARP";
				}
				else {
					reason = "ICMP";
				}
				if(ContainsString( report_up, "yes" )){
					report += "Host is alive (successful " + reason + " ping), Method: nmap";
				}
				if(ContainsString( log_nmap_output, "yes" )){
					report += "\nnmap command: " + join( list: argv_sp_only ) + "\n\n" + res;
					if(ContainsString( log_failed_nmap, "yes" ) && strlen( failed_nmap_report ) > 0){
						report += "\n\nFailed nmap calls / unexpected replies:" + failed_nmap_report;
					}
				}
				log_message( port: 0, data: report );
			}
			set_kb_item( name: "/tmp/ping/ICMP", value: 1 );
			exit( 0 );
		}
		else {
			if( res && ContainsString( res, "Nmap done" ) && ContainsString( res, "Host seems down" ) ){
				report_dead_methods += "\n\nHost is down (failed ARP/ICMP ping), Method: nmap with only -sP";
				if(ContainsString( log_nmap_output, "yes" )){
					report_dead_methods += "\nnmap command: " + join( list: argv_sp_only ) + "\n\n" + res;
				}
			}
			else {
				failed_nmap_report += "\n\n" + res;
			}
		}
	}
	if(ContainsString( icmp_ping, "yes" ) || ContainsString( arp_ping, "yes" )){
		argv_icmp = argv;
		argv_icmp[x++] = "-PE";
		argv_icmp[x++] = targetip;
		res = pread( cmd: "nmap", argv: argv_icmp );
		if(ContainsString( res, "Warning:  You are not root" )){
			log_message( port: 0, data: "WARNING: You requested the Nmap scan type -PE (ICMP echo probe) which requires root privileges but scanner is running under an unprivileged user. Nmap has used TCP ping scan instead, if you want use -PE start the scanner as root." );
		}
		if( res && egrep( pattern: pattern, string: res ) && !ContainsString( res, "Host seems down" ) ){
			if(ContainsString( report_up, "yes" ) || ContainsString( log_nmap_output, "yes" )){
				report = "";
				if( ContainsString( res, "received arp-response" ) ) {
					reason = "ARP";
				}
				else {
					reason = "ICMP";
				}
				if(ContainsString( report_up, "yes" )){
					report += "Host is alive (successful " + reason + " ping), Method: nmap";
				}
				if(ContainsString( log_nmap_output, "yes" )){
					report += "\nnmap command: " + join( list: argv_icmp ) + "\n\n" + res;
					if(ContainsString( log_failed_nmap, "yes" ) && strlen( failed_nmap_report ) > 0){
						report += "\n\nFailed nmap calls / unexpected replies:" + failed_nmap_report;
					}
				}
				log_message( port: 0, data: report );
			}
			set_kb_item( name: "/tmp/ping/ICMP", value: 1 );
			exit( 0 );
		}
		else {
			if( res && ContainsString( res, "Nmap done" ) && ContainsString( res, "Host seems down" ) ){
				report_dead_methods += "\n\nHost is down (failed ARP/ICMP ping), Method: nmap";
				if(ContainsString( log_nmap_output, "yes" )){
					report_dead_methods += "\nnmap command: " + join( list: argv_icmp ) + "\n\n" + res;
				}
				if( TARGET_IS_IPV6() ) {
					set_kb_item( name: "ICMPv6/EchoRequest/failed", value: TRUE );
				}
				else {
					set_kb_item( name: "ICMPv4/EchoRequest/failed", value: TRUE );
				}
			}
			else {
				failed_nmap_report += res + "\n\n";
			}
		}
	}
	if(ContainsString( tcp_ping, "yes" )){
		argv_tcp = argv;
		pa_ports = "21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080";
		nmap_pa_additional_ports = script_get_preference( name: "nmap additional ports for -PA", id: 10 );
		if(strlen( nmap_pa_additional_ports ) > 0){
			nmap_pa_additional_ports = str_replace( string: nmap_pa_additional_ports, find: " ", replace: "" );
			if( !check_pa_port_list( list: nmap_pa_additional_ports ) ){
				log_message( port: 0, data: "nmap additional ports for -PA has wrong format or contains an invalid port and was ignored. Please use a\ncomma separated list of ports without spaces. Example: 8080,3128,8000" );
				nmap_pa_additional_ports = "";
			}
			else {
				pa_ports += "," + nmap_pa_additional_ports;
			}
		}
		if( ContainsString( tcp_syn_ping_only, "yes" ) ){
			run_tcp_syn_ping( argv: argv, pa_ports: pa_ports, targetip: targetip, pattern: pattern, report_up: report_up, log_nmap_output: log_nmap_output, log_failed_nmap: log_failed_nmap );
		}
		else {
			argv_tcp[x++] = "-PA" + pa_ports;
			argv_tcp[x++] = targetip;
			res = pread( cmd: "nmap", argv: argv_tcp );
			if( res && egrep( pattern: pattern, string: res ) && !ContainsString( res, "Host seems down" ) ){
				if(ContainsString( report_up, "yes" ) || ContainsString( log_nmap_output, "yes" )){
					report = "";
					if(ContainsString( report_up, "yes" )){
						report += "Host is alive (successful TCP service ping), Method: nmap";
					}
					if(ContainsString( log_nmap_output, "yes" )){
						report += "\nnmap command: " + join( list: argv_tcp ) + "\n\n" + res;
						if(ContainsString( log_failed_nmap, "yes" ) && strlen( failed_nmap_report ) > 0){
							report += "\n\nFailed nmap calls / unexpected replies:" + failed_nmap_report;
						}
					}
					log_message( port: 0, data: report );
				}
				set_kb_item( name: "/tmp/ping/TCP", value: 1 );
				exit( 0 );
			}
			else {
				if( res && ContainsString( res, "Nmap done" ) && ContainsString( res, "Host seems down" ) ){
					report_dead_methods += "\n\nHost is down (failed TCP service ping), Method: nmap";
					if(ContainsString( log_nmap_output, "yes" )){
						report_dead_methods += "\nnmap command: " + join( list: argv_tcp ) + "\n\n" + res;
					}
				}
				else {
					failed_nmap_report += res + "\n\n";
				}
				if(ContainsString( tcp_syn_ping, "yes" )){
					run_tcp_syn_ping( argv: argv, pa_ports: pa_ports, targetip: targetip, pattern: pattern, report_up: report_up, log_nmap_output: log_nmap_output, log_failed_nmap: log_failed_nmap );
				}
			}
		}
	}
}
else {
	if(ContainsString( icmp_ping, "yes" )){
		PCAP_TIMEOUT = 3;
		if( TARGET_IS_IPV6() ){
			if( version_is_less( version: OPENVAS_VERSION, test_version: "20.8.0" ) ) {
				IP6_v = 0x60;
			}
			else {
				IP6_v = 6;
			}
			if(!IPPROTO_ICMPV6){
				IPPROTO_ICMPV6 = 58;
			}
			IP6_HLIM = 255;
			ICMP6_ECHO_REQ_TYPE = 128;
			ICMP6_ECHO_RES_TYPE = 129;
			ICMP_ID = rand() % 65536;
			set_byte_order( BYTE_ORDER_LITTLE_ENDIAN );
			ICMP_ID_REVERSE = mkdword( ICMP_ID );
			set_byte_order( BYTE_ORDER_BIG_ENDIAN );
			ICMP_ID_REVERSE = getword( blob: ICMP_ID_REVERSE );
			ip6_packet = forge_ipv6_packet( ip6_v: IP6_v, ip6_p: IPPROTO_ICMPV6, ip6_plen: 20, ip6_hlim: IP6_HLIM, ip6_src: ownip, ip6_dst: targetip );
			filter = "icmp6 and dst host " + ownip + " and src host " + targetip + " and ip6[40] = " + ICMP6_ECHO_RES_TYPE + " and ( ip6[44:2] = " + ICMP_ID + " or ip6[44:2] = " + ICMP_ID_REVERSE + " )";
			attempt = 2;
			ret = NULL;
			icmp_seq = 1;
			for(;!ret && attempt--;){
				data = rand_str( length: 56 );
				icmp6_packet = forge_icmp_v6_packet( ip6: ip6_packet, icmp_type: ICMP6_ECHO_REQ_TYPE, icmp_code: 0, icmp_seq: icmp_seq++, icmp_id: ICMP_ID, data: data );
				ret = send_v6packet( packet: icmp6_packet, pcap_active: TRUE, pcap_filter: filter, pcap_timeout: PCAP_TIMEOUT );
				if(ret){
					if(ContainsString( report_up, "yes" )){
						log_message( port: 0, data: "Host is alive (successful ICMP ping), Method: internal" );
					}
					set_kb_item( name: "/tmp/ping/ICMP", value: 1 );
					exit( 0 );
				}
			}
			report_dead_methods += "\nHost is down (failed ICMP ping), Method: internal";
			set_kb_item( name: "ICMPv6/EchoRequest/failed", value: TRUE );
		}
		else {
			ICMP_ECHO_REQ_TYPE = 8;
			ICMP_ECHO_RES_TYPE = 0;
			ICMP_ID = rand() % 65536;
			ip_packet = forge_ip_packet( ip_off: IP_DF, ip_p: IPPROTO_ICMP, ip_src: ownip, ip_dst: targetip );
			filter = "icmp and dst host " + ownip + " and src host " + targetip + " and icmp[0] = " + ICMP_ECHO_RES_TYPE + " and icmp[4:2] = " + ICMP_ID;
			attempt = 2;
			ret = NULL;
			icmp_seq = 1;
			for(;!ret && attempt--;){
				data = rand_str( length: 56 );
				icmp_packet = forge_icmp_packet( icmp_type: ICMP_ECHO_REQ_TYPE, icmp_code: 0, icmp_seq: icmp_seq++, icmp_id: ICMP_ID, data: data, ip: ip_packet );
				ret = send_packet( packet: icmp_packet, pcap_active: TRUE, pcap_filter: filter, pcap_timeout: PCAP_TIMEOUT );
				if(ret){
					if(ContainsString( report_up, "yes" )){
						log_message( port: 0, data: "Host is alive (successful ICMP ping), Method: internal" );
					}
					set_kb_item( name: "/tmp/ping/ICMP", value: 1 );
					exit( 0 );
				}
			}
			report_dead_methods += "\n\nHost is down (failed ICMP ping), Method: internal";
			set_kb_item( name: "ICMPv4/EchoRequest/failed", value: TRUE );
		}
	}
	if(ContainsString( tcp_ping, "yes" )){
		if(tcp_ping()){
			if(ContainsString( report_up, "yes" )){
				log_message( port: 0, data: "Host is alive (successful TCP service ping), Method: internal" );
			}
			set_kb_item( name: "/tmp/ping/TCP", value: 1 );
			exit( 0 );
		}
		report_dead_methods += "\n\nHost is down (failed TCP service ping), Method: internal";
	}
}
register_host_detail( name: "dead", value: 1 );
if(ContainsString( report_dead, "yes" )){
	if( ContainsString( use_nmap, "yes" ) && report_dead_methods == "" ){
		report_dead_methods += "\n\nMethod: nmap chosen but invocation of nmap failed due to unknown reasons.";
		if( !ContainsString( log_nmap_output, "yes" ) || !ContainsString( log_failed_nmap, "yes" ) ) {
			report_dead_methods += " Please set 'Log nmap output' and 'Log failed nmap calls' to 'yes' and re-run this test to get additional output.";
		}
		else {
			report_dead_methods += " Please see the output below for some hints on the failed nmap calls.\n\n" + failed_nmap_report;
		}
	}
	else {
		if(report_dead_methods != ""){
			report_dead_methods = " Used/configured checks:" + report_dead_methods;
		}
	}
	log_message( port: 0, data: "The remote host " + targetip + " was considered as dead." + report_dead_methods );
}
if(ContainsString( mark_dead, "yes" )){
	set_kb_item( name: "Host/dead", value: TRUE );
}
exit( 0 );

