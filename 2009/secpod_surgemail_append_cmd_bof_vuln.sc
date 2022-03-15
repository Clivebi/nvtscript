if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900840" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-15 09:32:43 +0200 (Tue, 15 Sep 2009)" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_cve_id( "CVE-2008-7182" );
	script_bugtraq_id( 30000 );
	script_name( "SurgeMail 'APPEND' Command Buffer Overflow Vulnerability" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/30739/" );
	script_xref( name: "URL", value: "http://www.milw0rm.com/exploits/5968" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/496482" );
	script_xref( name: "URL", value: "http://www.netwinsite.com/surgemail/help/updates.htm" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "secpod_surgemail_detect.sc" );
	script_mandatory_keys( "SurgeMail/Ver" );
	script_tag( name: "impact", value: "Successful exploitation could allow remote authenticated users to cause a
  Denial of Service and possibly execute arbitrary code in the victim's system." );
	script_tag( name: "affected", value: "SurgeMail version prior to 3.9g2" );
	script_tag( name: "insight", value: "Buffer overflow in the IMAP service is caused due the way it handles the
  APPEND command which can be exploited via a long first argument." );
	script_tag( name: "solution", value: "Upgrade to SurgeMail version 3.9g2 or later." );
	script_tag( name: "summary", value: "This host is running SurgeMail and is prone to Buffer Overflow
  vulnerability." );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
require("version_func.inc.sc");
surgemailVer = get_kb_item( "SurgeMail/Ver" );
if(!surgemailVer){
	exit( 0 );
}
if(version_is_less( version: surgemailVer, test_version: "3.9.g2" )){
	report = report_fixed_ver( installed_version: surgemailVer, fixed_version: "3.9.g2" );
	security_message( port: 0, data: report );
}

