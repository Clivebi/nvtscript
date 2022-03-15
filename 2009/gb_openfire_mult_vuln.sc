CPE = "cpe:/a:igniterealtime:openfire";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.800354" );
	script_version( "$Revision: 14031 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-07 11:47:29 +0100 (Thu, 07 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2009-02-11 16:51:00 +0100 (Wed, 11 Feb 2009)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_cve_id( "CVE-2009-0496", "CVE-2009-0497" );
	script_bugtraq_id( 32935, 32937, 32938, 32939, 32940, 32943, 32944, 32945 );
	script_name( "Ignite Realtime OpenFire Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_openfire_detect.sc" );
	script_require_ports( "Services/www", 9090 );
	script_mandatory_keys( "OpenFire/Installed" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/33452" );
	script_xref( name: "URL", value: "http://svn.igniterealtime.org/svn/repos/openfire/trunk/src/web/log.jsp" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/archive/1/archive/1/499880/100/0/threaded" );
	script_tag( name: "impact", value: "Attacker may leverage this issue by executing arbitrary script code or
  injecting HTML or JavaScript code in the context of the affected system
  and can cause directory traversal or XSS attack." );
	script_tag( name: "affected", value: "Ignite Realtime Openfire version prior to 3.6.3 on all platforms." );
	script_tag( name: "insight", value: "Application fails to sanitise the user inputs in,

  - log parameter to logviewer.jsp and log.jsp files,

  - search parameter to group-summary.jsp file,

  - username parameter to user-properties.jsp file,

  - logDir, maxTotalSize, maxFileSize, maxDays, and logTimeout parameters
    to audit-policy.jsp file,

  - propName parameter to server-properties.jsp file,

  - roomconfig_roomname and roomconfig_roomdesc parameters to
  muc-room-edit-form.jsp file." );
	script_tag( name: "solution", value: "Upgrade to OpenFire version 3.6.3 or later." );
	script_tag( name: "summary", value: "This host is running OpenFire and is prone to multiple
  vulnerabilities." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
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
if(version_is_less( version: vers, test_version: "3.6.3" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "3.6.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

