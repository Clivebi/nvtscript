CPE = "cpe:/a:progress:sitefinity";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.112222" );
	script_version( "2021-05-27T09:28:58+0000" );
	script_tag( name: "last_modification", value: "2021-05-27 09:28:58 +0000 (Thu, 27 May 2021)" );
	script_tag( name: "creation_date", value: "2018-02-13 13:52:34 +0100 (Tue, 13 Feb 2018)" );
	script_tag( name: "cvss_base", value: "6.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-05 19:58:00 +0000 (Mon, 05 Mar 2018)" );
	script_cve_id( "CVE-2017-18175", "CVE-2017-18176", "CVE-2017-18177", "CVE-2017-18178", "CVE-2017-18179" );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_name( "Sitefinity < 10.1 Multiple Vulnerabilities" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "gb_sitefinity_detect.sc" );
	script_mandatory_keys( "sitefinity/detected" );
	script_tag( name: "summary", value: "Sitefinity is prone to multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Sitefinity is prone to the following vulnerabilities:

1) Open Redirect Vulnerabilities
Several scripts of Sitefinity are vulnerable to an open redirect. This
vulnerability allows an attacker to redirect the victim to any site by using a
manipulated link (e.g. a manipulated link in a phishing mail, forum or a
guestbook).

The redirection target could imitate the original site and might
be used for phishing attacks or for running browser exploits to infect the
victimas machine with malware. Because the server name in the manipulated link
is identical to the original site, phishing attempts have a more trustworthy
appearance.

In the first instance of this vulnerability, the open redirect will forward
an authentication token to the attacker controlled site, which can be abused
by the attacker to initiate new sessions for the affected user.

2) Broken Session Management
During the authentication process, Sitefinity creates an authentication token
\"wrap_access_token\", which is further used as a GET parameter to initiate a
valid session if the supplied credentials have been verified to be correct.
Transporting this token as GET parameter causes unnecessary exposure of the
sensitive token, as it might end up in proxy or access logs.

Furthermore, this token is not tied to the session ID and can be used to
generate new valid sessions for the user, even if the initial session has been
terminated by the user.

The token will also survive a password change (e.g. if
the user suspects misuse of his account) and can still be used to initiate new
sessions. During the timeframe of testing, no expiry of the token could be
observed. The wrap_access_token can thus be seen as a \"Kerberos golden ticket\"
for Sitefinity.

3) Permanent Cross-Site Scripting
Multiple scripts do not properly sanitize/encode user input, which leads to
permanent cross site scripting vulnerabilities.

Furthermore, the web application allows users to upload HTML files,
which are provided via the same domain, allowing an authenticated attacker
to access arbitrary information and execute arbitrary functions of Sitefinity on behalf of other users.
These vulnerabilities can be used by attackers to circumvent segregation of duties." );
	script_tag( name: "affected", value: "Sitefinity before version 10.1." );
	script_tag( name: "solution", value: "Update to version 10.1 or later." );
	script_xref( name: "URL", value: "https://www.sec-consult.com/en/blog/advisories/multiple-vulnerabilities-in-progress-sitefinity/index.html" );
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
if(version_is_less( version: version, test_version: "10.1" )){
	report = report_fixed_ver( installed_version: version, fixed_version: "10.1" );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

