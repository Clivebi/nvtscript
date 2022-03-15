if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.900951" );
	script_version( "2021-09-01T12:57:33+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 12:57:33 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2009-09-29 09:16:03 +0200 (Tue, 29 Sep 2009)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_cve_id( "CVE-2009-3051" );
	script_bugtraq_id( 35940 );
	script_name( "SILC Client Nickname Field Format String Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2009 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "secpod_silc_prdts_detect.sc" );
	script_mandatory_keys( "SILC/Client/Ver" );
	script_tag( name: "impact", value: "Attackers can exploit this iisue to execute arbitrary code in the
  context of the affected application and compromise the system." );
	script_tag( name: "affected", value: "SILC Client prior to 1.1.8

  SILC Toolkit prior to 1.1.10" );
	script_tag( name: "insight", value: "A format string error occurs in 'lib/silcclient/client_entry.c' while
  processing format string specifiers in the nickname field." );
	script_tag( name: "summary", value: "This host has SILC Client/Toolkit installed, and is prone
  to Format String vulnerability." );
	script_tag( name: "solution", value: "Apply the patch or upgrade to SILC Client 1.1.8." );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2009/2150" );
	script_xref( name: "URL", value: "http://www.openwall.com/lists/oss-security/2009/09/03/5" );
	script_tag( name: "qod_type", value: "executable_version" );
	script_tag( name: "solution_type", value: "VendorFix" );
	exit( 0 );
}
CPE = "cpe:/a:silcnet:silc_client";
require("host_details.inc.sc");
require("version_func.inc.sc");
if(version = get_app_version( cpe: CPE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "1.1.8" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "1.1.8" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

