CPE = "cpe:/a:dovecot:dovecot";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800030" );
	script_version( "2020-08-14T08:58:27+0000" );
	script_tag( name: "last_modification", value: "2020-08-14 08:58:27 +0000 (Fri, 14 Aug 2020)" );
	script_tag( name: "creation_date", value: "2008-10-17 14:35:03 +0200 (Fri, 17 Oct 2008)" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_cve_id( "CVE-2008-4577", "CVE-2008-4578" );
	script_bugtraq_id( 31587 );
	script_name( "Dovecot ACL Plugin Security Bypass Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2008 Greenbone Networks GmbH" );
	script_family( "Privilege escalation" );
	script_dependencies( "gb_dovecot_consolidation.sc" );
	script_mandatory_keys( "dovecot/detected" );
	script_xref( name: "URL", value: "http://www.frsirt.com/english/advisories/2008/2745" );
	script_xref( name: "URL", value: "http://www.dovecot.org/list/dovecot-news/2008-October/000085.html" );
	script_tag( name: "impact", value: "Successful attack could allow malicious people to bypass certain
  security restrictions or manipulate certain data." );
	script_tag( name: "affected", value: "Dovecot versions prior to 1.1.4." );
	script_tag( name: "insight", value: "The flaws are due to:

  - the ACL plugin interprets negative access rights as positive access rights,
  potentially giving an unprivileged user access to restricted resources.

  - an error in the ACL plugin when imposing mailbox creation restrictions to
  to create parent/child/child mailboxes." );
	script_tag( name: "solution", value: "Upgrade to Dovecot version 1.1.4 or later." );
	script_tag( name: "summary", value: "This host has Dovecot ACL Plugin installed and is prone to
  multiple security bypass vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
version = infos["version"];
location = infos["location"];
if(version_is_less( version: version, test_version: "1.1.4" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.4", install_path: location );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

