if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11135" );
	script_version( "2020-10-08T13:07:46+0000" );
	script_tag( name: "last_modification", value: "2020-10-08 13:07:46 +0000 (Thu, 08 Oct 2020)" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_xref( name: "IAVA", value: "2001-a-0004" );
	script_bugtraq_id( 2524 );
	script_cve_id( "CVE-2001-0154" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "Bugbear worm" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_copyright( "Copyright (C) 2005 Michel Arboi & Thomas Reinke" );
	script_family( "Malware" );
	script_require_ports( 36794 );
	script_dependencies( "find_service.sc" );
	script_tag( name: "solution", value: "- Use an Anti-Virus package to remove it.

  - Close your Windows shares

  - Update your IE browser

  See 'Incorrect MIME Header Can Cause IE to Execute E-mail Attachment'" );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "summary", value: "BugBear backdoor is listening on this port." );
	script_tag( name: "impact", value: "An attacker may connect to it to retrieve secret
  information, e.g. passwords or credit card numbers." );
	script_tag( name: "insight", value: "The BugBear worm includes a key logger and can stop
  antivirus or personal firewall software. It propagates itself through email and open
  Windows shares.

  Depending on the antivirus vendor, it is known as: Tanatos,
  I-Worm.Tanatos, NATOSTA.A, W32/Bugbear-A, Tanatos, W32/Bugbear@MM,
  WORM_BUGBEAR.A, Win32.BugBear." );
	script_xref( name: "URL", value: "https://docs.microsoft.com/en-us/security-updates/securitybulletins/2001/ms01-020" );
	script_xref( name: "URL", value: "http://www.sophos.com/virusinfo/analyses/w32bugbeara.html" );
	script_xref( name: "URL", value: "http://www.ealaddin.com/news/2002/esafe/bugbear.asp" );
	script_xref( name: "URL", value: "http://securityresponse.symantec.com/avcenter/venc/data/w32.bugbear@mm.html" );
	script_xref( name: "URL", value: "http://vil.nai.com/vil/content/v_99728.htm" );
	script_xref( name: "URL", value: "http://online.securityfocus.com/news/1034" );
	script_xref( name: "URL", value: "http://support.microsoft.com/default.aspx?scid=KB;en-us;329770&" );
	exit( 0 );
}
require("host_details.inc.sc");
require("misc_func.inc.sc");
port = 36794;
if(!get_port_state( port )){
	exit( 0 );
}
soc = open_sock_tcp( port );
if(!soc){
	exit( 0 );
}
send( socket: soc, data: "p" );
r = recv( socket: soc, length: 65536 );
close( soc );
if(ContainsString( r, "ID:" )){
	report = "The Bugbear worm was detected on the target system.";
	security_message( data: report, port: port );
	exit( 0 );
}
msg = "
This port is usually used by the BugBear backdoor.
Although the scanner was unable to get an answer from the worm,
you'd better check your machine with an up to date
antivirus scanner.";
security_message( port: port, data: msg );

