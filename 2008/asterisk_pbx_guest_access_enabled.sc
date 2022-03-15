CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.9999993" );
	script_version( "$Revision: 10415 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-07-05 12:51:54 +0200 (Thu, 05 Jul 2018) $" );
	script_tag( name: "creation_date", value: "2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "3.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:N/I:P/A:N" );
	script_name( "Asterisk PBX SIP Service Guest Access Enabled" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "This script is Copyright (C) 2008 Ferdy Riphagen" );
	script_dependencies( "secpod_asterisk_detect.sc", "global_settings.sc" );
	script_mandatory_keys( "Asterisk-PBX/Installed" );
	script_exclude_keys( "keys/islocalhost" );
	script_xref( name: "URL", value: "http://www.voip-info.org/wiki/index.php?page=Asterisk+sip+allowguest" );
	script_tag( name: "solution", value: "If guest access is not needed, disable it by setting 'allowguest=no'
  in the sip.conf file." );
	script_tag( name: "summary", value: "Asterisk PBX SIP service guest access is enabled.

  Description :

  Asterisk an open-source PBX is installed on the remote system.
  The SIP service is accepting SIP peers to use the proxy server
  as guest users. Unauthenticated users can use the proxy
  without supplying the required 'more secure' authentication.

  Guest access is enabled by default if 'allowguest=no' is not set
  in 'sip.conf'. Guest peers use the context defined under the
  general section and the restrictions set in the Asterisk config
  files." );
	script_tag( name: "solution_type", value: "Mitigation" );
	script_tag( name: "qod_type", value: "remote_vul" );
	exit( 0 );
}
require("sip.inc.sc");
require("host_details.inc.sc");
if(islocalhost()){
	exit( 0 );
}
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_location_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
proto = infos["proto"];
rpeer = NASLString( "NotExistingPeer", rand() % 900 + 100, "@" );
lpeer = NASLString( "OpenVAS", rand() % 900 + 100, "@" );
invite = NASLString( "INVITE sip:", rpeer, get_host_name(), " SIP/2.0", "\\r\\n", "Via: SIP/2.0/", toupper( proto ), " ", this_host(), ":", port, "\\r\\n", "To: <sip:", rpeer, get_host_name(), ":", port, ">\\r\\n", "From: <sip:", lpeer, this_host(), ":", port, ">\\r\\n", "Call-ID: ", rand(), "\\r\\n", "CSeq: ", rand(), " INVITE\\r\\n", "Contact: <sip:", lpeer, this_host(), ">\\r\\n", "Content-Length: 0\\r\\n\\r\\n" );
res = sip_send_recv( port: port, data: invite, proto: proto );
if(isnull( res )){
	exit( 0 );
}
if(ContainsString( res, "SIP/2.0 404 Not Found" ) || ContainsString( res, "SIP/2.0 100 Trying" )){
	set_kb_item( name: "sip/guest_access/" + port + "/" + proto, value: TRUE );
	security_message( port: port, proto: proto );
	exit( 0 );
}
exit( 99 );

