if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.902650" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_cve_id( "CVE-2011-4602", "CVE-2011-4603", "CVE-2011-4601" );
	script_bugtraq_id( 51070, 51074 );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-12-21 11:02:55 +0530 (Wed, 21 Dec 2011)" );
	script_name( "Pidgin XMPP And SILC Protocols Denial of Service Vulnerabilities (Windows)" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=57" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=58" );
	script_xref( name: "URL", value: "http://pidgin.im/news/security/?id=59" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_pidgin_detect_win.sc" );
	script_mandatory_keys( "Pidgin/Win/Ver" );
	script_tag( name: "impact", value: "Successful exploitation will allow remote attackers to cause the application
  to crash, denying service to legitimate users." );
	script_tag( name: "affected", value: "Pidgin versions prior to 2.10.1" );
	script_tag( name: "insight", value: "Multiplw flaws are due to

  - An error in the silc_channel_message function in ops.c in the SILC
    protocol plugin in libpurple, which fails to validate that a piece of text
    was UTF-8 when receiving various incoming messages.

  - An error in the XMPP protocol plugin in libpurple, which fails to ensure
    that the incoming message contained all required fields when receiving
    various stanzas related to voice and video chat.

  - An error in the family_feedbag.c in the oscar protocol plugin, which fails
    to validate that a piece of text was UTF-8 when receiving various incoming
    messages." );
	script_tag( name: "solution", value: "Upgrade to Pidgin version 2.10.1 or later." );
	script_tag( name: "summary", value: "This host is installed with Pidgin and is prone to denial of
  service vulnerabilities." );
	script_tag( name: "qod_type", value: "registry" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
pidginVer = get_kb_item( "Pidgin/Win/Ver" );
if(pidginVer != NULL){
	if(version_is_less( version: pidginVer, test_version: "2.10.1" )){
		report = report_fixed_ver( installed_version: pidginVer, fixed_version: "2.10.1" );
		security_message( port: 0, data: report );
	}
}

