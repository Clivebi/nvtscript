CPE = "cpe:/a:cyrus:imap";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103249" );
	script_version( "2019-06-26T09:58:31+0000" );
	script_tag( name: "last_modification", value: "2019-06-26 09:58:31 +0000 (Wed, 26 Jun 2019)" );
	script_tag( name: "creation_date", value: "2011-09-12 14:00:02 +0200 (Mon, 12 Sep 2011)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2011-3208" );
	script_bugtraq_id( 49534 );
	script_name( "Cyrus IMAP Server 'split_wildmats()' Remote Buffer Overflow Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_family( "Buffer overflow" );
	script_copyright( "This script is Copyright (C) 2011 Greenbone Networks GmbH" );
	script_dependencies( "secpod_cyrus_imap_server_detect.sc" );
	script_mandatory_keys( "cyrus/imap_server/detected" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/49534" );
	script_xref( name: "URL", value: "http://asg.andrew.cmu.edu/archive/message.php?mailbox=archive.cyrus-announce&msg=199" );
	script_xref( name: "URL", value: "http://asg.andrew.cmu.edu/archive/message.php?mailbox=archive.cyrus-announce&msg=200" );
	script_xref( name: "URL", value: "http://cyrusimap.web.cmu.edu/" );
	script_tag( name: "impact", value: "Attackers can execute arbitrary code in the context of the affected
  application. Failed exploit attempts will result in a denial-of-service condition." );
	script_tag( name: "affected", value: "Cyrus IMAP Server versions prior to 2.3.17 and 2.4.11 are vulnerable." );
	script_tag( name: "summary", value: "Cyrus IMAP Server is prone to a remote buffer-overflow vulnerability because the
  application fails to properly bounds check user-supplied data before copying it into an
  insufficiently sized buffer." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more information." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!vers = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_in_range( version: vers, test_version: "2.4", test_version2: "2.4.10" ) || version_in_range( version: vers, test_version: "2.3", test_version2: "2.3.16" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "2.3.17/2.4.11" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

