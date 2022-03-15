CPE = "cpe:/a:ipswitch:imail_server";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.11271" );
	script_version( "$Revision: 13975 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-04 10:32:08 +0100 (Mon, 04 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2005-11-03 14:08:04 +0100 (Thu, 03 Nov 2005)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:N/A:N" );
	script_name( "IMail account hijack" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2003 Michel Arboi" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ipswitch_imail_server_detect.sc" );
	script_mandatory_keys( "Ipswitch/IMail/detected" );
	script_tag( name: "solution", value: "Upgrade to IMail 7.06 or turn off the 'ignore source address in
  security check' option." );
	script_tag( name: "summary", value: "The remote host is running IMail web interface. In this version,
  the session is maintained via the URL. It will be disclosed in the Referer field
  if you receive an email with external links (e.g. images)" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(!version = get_app_version( cpe: CPE, nofork: TRUE )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "7.06" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "7.06" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

