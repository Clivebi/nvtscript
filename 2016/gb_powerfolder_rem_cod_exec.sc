CPE = "cpe:/a:powerfolder:powerfolder";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107010" );
	script_version( "2021-04-28T02:19:23+0000" );
	script_tag( name: "last_modification", value: "2021-04-28 02:19:23 +0000 (Wed, 28 Apr 2021)" );
	script_tag( name: "creation_date", value: "2016-06-07 06:40:16 +0200 (Tue, 07 Jun 2016)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "PowerFolder < 10.5.394 RCE Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_powerfolder_http_detect.sc" );
	script_mandatory_keys( "powerfolder/detected" );
	script_tag( name: "summary", value: "PowerFolder is prone to a remote code execution (RCE) vulnerability." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The data exchange method between PowerFolder server and clients
  allows deserialization of untrusted data, which can be exploited to execute arbitrary code." );
	script_tag( name: "impact", value: "Successful exploitation allows an attacker unauthorized disclosure
  of information, unauthorized modification and disruption of service." );
	script_tag( name: "affected", value: "PowerFolder version 10.4.321 (Other version might be also affected)." );
	script_tag( name: "solution", value: "Update PowerFolder to version 10 SP5 (10.5.394) or later." );
	script_xref( name: "URL", value: "https://www.exploit-db.com/exploits/39854/" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/137172/PowerFolder-10.4.321-Remote-Code-Execution.html" );
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
if(version_is_less_equal( version: version, test_version: "10.4.321" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10 SP5 (10.5.394)" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

