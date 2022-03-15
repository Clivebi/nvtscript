CPE = "cpe:/h:tandberg:*";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.103788" );
	script_bugtraq_id( 42827 );
	script_cve_id( "CVE-2009-3947" );
	script_version( "$Revision: 14186 $" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_name( "TANDBERG MXP Series Video Conferencing Device Remote Denial Of Service Vulnerability" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-14 14:57:54 +0100 (Thu, 14 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-09-12 13:33:18 +0200 (Thu, 12 Sep 2013)" );
	script_category( ACT_GATHER_INFO );
	script_family( "Denial of Service" );
	script_copyright( "This script is Copyright (C) 2013 Greenbone Networks GmbH" );
	script_dependencies( "gb_tandberg_devices_detect.sc" );
	script_require_ports( "Services/telnet", 23 );
	script_mandatory_keys( "tandberg_codec_release" );
	script_xref( name: "URL", value: "http://www.securityfocus.com/bid/42827" );
	script_xref( name: "URL", value: "http://www.tandberg.com/products/mxp_user_guide.jsp" );
	script_xref( name: "URL", value: "ftp://ftp.tandberg.com/pub/software/endpoints/mxp/TANDBERG%20MXP%20Endpoints%20Software%20Release%20Notes%20%28F9%29.pdf" );
	script_tag( name: "impact", value: "A successful exploit will cause the device to crash, denying service
  to legitimate users." );
	script_tag( name: "vuldetect", value: "Check if Codec Release is <= F8.2." );
	script_tag( name: "insight", value: "The devices are exposed to a remote denial of service issue because
  they fail to properly validate user-supplied data." );
	script_tag( name: "solution", value: "Updates are available. Please see the references for more details." );
	script_tag( name: "summary", value: "TANDBERG MXP Series devices are prone to a remote denial-of-service
  vulnerability." );
	script_tag( name: "affected", value: "TANDBERG MXP Series devices with version F8.2 is vulnerable, other
  versions may also be affected." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(vers = get_kb_item( "tandberg_codec_release" )){
	version = eregmatch( pattern: "F([0-9.]+)", string: vers );
	if(isnull( version[1] )){
		exit( 0 );
	}
	if(version_is_less_equal( version: version[1], test_version: "8.2" )){
		report = report_fixed_ver( installed_version: version[1], fixed_version: "9.0" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

