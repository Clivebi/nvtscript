CPE = "cpe:/a:puppet:enterprise";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106582" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-02-09 13:27:28 +0700 (Thu, 09 Feb 2017)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-10 15:40:00 +0000 (Wed, 10 Jul 2019)" );
	script_cve_id( "CVE-2016-9686" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Puppet Enterprise < 2016.4.3 / 2016.5 < 2016.5.2 DoS Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Denial of Service" );
	script_dependencies( "gb_puppet_enterprise_detect.sc" );
	script_mandatory_keys( "puppet_enterprise/installed" );
	script_tag( name: "summary", value: "Puppet Enterprise is prone to a denial of service vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The Puppet Communications Protocol (PCP) broker incorrectly validates
  message header sizes. An attacker could use this vulnerability to crash the PCP broker, preventing commands from
  being sent to agents." );
	script_tag( name: "affected", value: "Puppet Enterprise 2015.3.x and 2016.x." );
	script_tag( name: "solution", value: "Update to version 2016.4.3, 2016.5.2 or later." );
	script_xref( name: "URL", value: "https://puppet.com/security/cve/cve-2016-9686" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!version = get_app_version( cpe: CPE, port: port )){
	exit( 0 );
}
if(version_is_less( version: version, test_version: "2016.4.3" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "2016.4.3" );
	security_message( port: port, data: report );
	exit( 0 );
}
if(IsMatchRegexp( version, "^2016\\.5" )){
	if(version_is_less( version: version, test_version: "2016.5.2" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "2016.5.2" );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 0 );

