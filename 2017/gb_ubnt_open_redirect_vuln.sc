if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106985" );
	script_version( "$Revision: 12106 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-10-26 08:33:36 +0200 (Fri, 26 Oct 2018) $" );
	script_tag( name: "creation_date", value: "2017-07-25 14:45:24 +0700 (Tue, 25 Jul 2017)" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Ubiquiti Networks Products Open Redirect Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "This script is Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_ubnt_discovery_protocol_detect.sc" );
	script_mandatory_keys( "ubnt_discovery_proto/detected", "ubnt_discovery_proto/firmware" );
	script_tag( name: "summary", value: "Multiple Ubiquiti Networks products are prone to an open redirect
vulnerability." );
	script_tag( name: "insight", value: "A open redirect vulnerability can be triggered by luring an attacked user
to authenticate to a Ubiquiti AirOS device by clicking on a crafted link." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "solution", value: "Upgrade to firmware version 6.0.3 (XM), 1.3.5 (SW) or later." );
	script_xref( name: "URL", value: "https://www.sec-consult.com/fxdata/seccons/prod/temedia/advisories_txt/20170724-1_Ubiquiti_Networks_-Open_Redirect_in_Login_Page_v10.txt" );
	exit( 0 );
}
require("version_func.inc.sc");
fw = get_kb_item( "ubnt_discovery_proto/firmware" );
if(!fw || !IsMatchRegexp( fw, "^(XM|SW)" )){
	exit( 0 );
}
vers = eregmatch( pattern: "\\.v([0-9]\\.[0-9]\\.[0-9])", string: fw );
if(isnull( vers[1] )){
	exit( 0 );
}
version = vers[1];
if(IsMatchRegexp( fw, "^XM" )){
	if(version_is_less( version: version, test_version: "6.0.3" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "6.0.3" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
if(IsMatchRegexp( fw, "^SW" )){
	if(version_is_less( version: version, test_version: "1.3.5" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "1.3.5" );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
exit( 99 );

