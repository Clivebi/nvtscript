CPE = "cpe:/a:squid-cache:squid";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107297" );
	script_version( "2021-05-21T06:00:13+0200" );
	script_cve_id( "CVE-2018-1000027" );
	script_tag( name: "last_modification", value: "2021-05-21 06:00:13 +0200 (Fri, 21 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-09 19:08:28 +0100 (Fri, 09 Feb 2018)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-07-17 16:15:00 +0000 (Wed, 17 Jul 2019)" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Squid Proxy Cache Security Update Advisory SQUID-2018:2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_squid_detect.sc" );
	script_mandatory_keys( "squid_proxy_server/installed" );
	script_tag( name: "summary", value: "Squid is vulnerable to denial of service attack
  when processing ESI responses." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Due to incorrect pointer handling Squid is vulnerable
  to denial of service attack when processing ESI responses or downloading intermediate CA
  certificates." );
	script_tag( name: "impact", value: "This problem allows a remote server delivering certain
  ESI response syntax to trigger a denial of service for all clients accessing the Squid service." );
	script_tag( name: "affected", value: "Squid 3.x -> 3.5.27, Squid 4.x -> 4.0.22 with specific
  deployment variants described in the referenced Advisory." );
	script_tag( name: "solution", value: "Updated Packages:

  This bug is fixed by Squid version 4.0.23.

  In addition, patches addressing this problem for the stable
  releases can be found in our patch archives for Squid 3.5 and Squid 4.

  If you are using a prepackaged version of Squid then please refer
  to the package vendor for availability information on updated
  packages." );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Advisories/SQUID-2018_2.txt" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Versions/v3/3.5/changesets/SQUID-2018_2.patch" );
	script_xref( name: "URL", value: "http://www.squid-cache.org/Versions/v4/changesets/SQUID-2018_2.patch" );
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
if( IsMatchRegexp( version, "^3\\." ) ){
	if(version_is_less_equal( version: version, test_version: "3.5.27" )){
		report = report_fixed_ver( installed_version: version, fixed_version: "See references" );
	}
}
else {
	if(IsMatchRegexp( version, "^4\\." )){
		if(version_is_less_equal( version: version, test_version: "4.0.22" )){
			report = report_fixed_ver( installed_version: version, fixed_version: "4.0.23" );
		}
	}
}
if(!isnull( report )){
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

