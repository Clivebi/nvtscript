CPE = "cpe:/a:pidgin:pidgin";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900941" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_cve_id( "CVE-2009-2703", "CVE-2009-3083", "CVE-2009-3084", "CVE-2009-3085" );
	script_bugtraq_id( 36277 );
	script_name( "Pidgin Multiple Denial Of Service Vulnerabilities (Linux)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_pidgin_detect_lin.sc" );
	script_mandatory_keys( "Pidgin/Lin/Ver" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/36601" );
	script_xref( name: "URL", value: "http://developer.pidgin.im/ticket/10159" );
	script_xref( name: "URL", value: "http://www.pidgin.im/news/security/?id=37" );
	script_xref( name: "URL", value: "http://www.pidgin.im/news/security/?id=38" );
	script_xref( name: "URL", value: "http://www.pidgin.im/news/security/?id=39" );
	script_xref( name: "URL", value: "http://www.pidgin.im/news/security/?id=40" );
	script_tag( name: "impact", value: "Attackers can exploit this issue to execute arbitrary code, corrupt memory
  and cause the application to crash." );
	script_tag( name: "affected", value: "Pidgin version prior to 2.6.2 on Linux." );
	script_tag( name: "insight", value: "- An error in libpurple/protocols/irc/msgs.c in the IRC protocol plugin in
  libpurple can trigger a NULL-pointer dereference when processing TOPIC
  messages which lack a topic string.

  - An error in the 'msn_slp_sip_recv' function in libpurple/protocols/msn/slp.c
  in the MSN protocol can trigger a NULL-pointer dereference via an SLP invite
  message missing expected fields.

  - An error in the 'msn_slp_process_msg' function in libpurple/protocols/msn/
  slpcall.c in the MSN protocol when converting the encoding of a handwritten
  message can be exploited by improper utilisation of uninitialised variables.

  - An error in the XMPP protocol plugin in libpurple is fails to handle an
  error IQ stanza during an attempted fetch of a custom smiley is processed
  via XHTML-IM content with cid: images." );
	script_tag( name: "solution", value: "Upgrade to Pidgin version 2.6.2." );
	script_tag( name: "summary", value: "This host has Pidgin installed and is prone to multiple Denial of
  Service vulnerabilities." );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!ver = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: ver, test_version: "2.6.2" )){
	report = report_fixed_ver( installed_version: ver, fixed_version: "2.6.2" );
	security_message( data: report );
	exit( 0 );
}
exit( 99 );

