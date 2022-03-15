if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.106110" );
	script_version( "2020-05-14T13:01:46+0000" );
	script_tag( name: "last_modification", value: "2020-05-14 13:01:46 +0000 (Thu, 14 May 2020)" );
	script_tag( name: "creation_date", value: "2016-06-24 16:45:17 +0700 (Fri, 24 Jun 2016)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:C/I:C/A:N" );
	script_cve_id( "CVE-2016-3962", "CVE-2016-3988", "CVE-2016-3989" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Meinberg LANTIME < 6.20.004 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_meinberg_lantime_detect.sc" );
	script_mandatory_keys( "meinberg_lantime/detected" );
	script_tag( name: "summary", value: "Meinberg LANTIME is prone to multiple vulnerabilies." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Meinberg LANTIME is prone to multiple vulnerabilies:

  Remote stack buffer overflow vulnerability involving parsing of parameter in POST request in function
  provides privilege of web server 'nobody'. (CVE-2016-3962)

  Remote stack buffer overflow vulnerability is present while parsing nine different parameters in POST
  request in function. (CVE-2016-3988)

  Weak access controls allow for privilege escalation from 'nobody' to 'root' user. 'nobody' has permissions
  to alter script that can only run as 'root'. (CVE-2016-3989)" );
	script_tag( name: "impact", value: "Successful exploitation of these vulnerabilities could cause a buffer
  overflow condition that may allow escalation to root privileges." );
	script_tag( name: "affected", value: "Version prior to 6.20.004 on IMS-LANTIME M3000, IMS-LANTIME M1000,
  IMS-LANTIME M500, LANTIME M900, LANTIME M600, LANTIME M400, LANTIME M300, LANTIME M200 and LANTIME M100." );
	script_tag( name: "solution", value: "Upgrade to Version 6.20.004 or later." );
	script_xref( name: "URL", value: "https://ics-cert.us-cert.gov/advisories/ICSA-16-175-03" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:meinberg:lantime_m3000",
	 "cpe:/a:meinberg:lantime_m1000",
	 "cpe:/a:meinberg:lantime_m500",
	 "cpe:/a:meinberg:lantime_m900",
	 "cpe:/a:meinberg:lantime_m600",
	 "cpe:/a:meinberg:lantime_m400",
	 "cpe:/a:meinberg:lantime_m300",
	 "cpe:/a:meinberg:lantime_m200",
	 "cpe:/a:meinberg:lantime_m100" );
if(!infos = get_app_version_from_list( cpe_list: cpe_list, nofork: TRUE )){
	exit( 0 );
}
vers = infos["version"];
if(version_is_less( version: vers, test_version: "6.20.004" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "6.20.004" );
	security_message( port: 0, data: report );
	exit( 0 );
}
exit( 99 );

