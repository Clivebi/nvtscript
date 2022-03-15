if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.17307" );
	script_version( "2020-10-08T13:07:46+0000" );
	script_tag( name: "last_modification", value: "2020-10-08 13:07:46 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_bugtraq_id( 12705 );
	script_cve_id( "CVE-2005-0581", "CVE-2005-0582", "CVE-2005-0583" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_name( "CA License Service Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2005 KK Liu" );
	script_family( "Gain a shell remotely" );
	script_dependencies( "find_service.sc" );
	script_require_ports( 10202, 10203, 10204 );
	script_xref( name: "URL", value: "http://www.eeye.com/html/research/advisories/AD20050302.html" );
	script_xref( name: "URL", value: "http://supportconnectw.ca.com/public/ca_common_docs/security_notice.asp" );
	script_tag( name: "solution", value: "See the references for more information." );
	script_tag( name: "summary", value: "The remote host is running the Computer Associate License Application.

  The remote version of this software is vulnerable to several flaws which
  may allow a remote attacker to execute arbitrary code on the remote host
  with the SYSTEM privileges." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
req = "A0 GETCONFIG SELF 0 <EOM>\r\n";
for port in make_list( 10202,
	 10203,
	 10204 ) {
	if(get_port_state( port )){
		soc = open_sock_tcp( port );
		if(soc){
			send( socket: soc, data: req );
			r = recv( socket: soc, length: 620 );
			close( soc );
			if(strlen( r ) > 0){
				chkstr = strstr( r, "VERSION<" );
				if(chkstr){
					if(egrep( pattern: "VERSION<[0-9] 1\\.(5[3-9].*|60.*|61(\\.[0-8])?)>", string: chkstr )){
						security_message( port: port );
					}
				}
			}
		}
	}
}
exit( 0 );

