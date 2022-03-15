if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.107243" );
	script_version( "2021-09-20T15:26:26+0000" );
	script_cve_id( "CVE-2017-14417", "CVE-2017-14418" );
	script_tag( name: "last_modification", value: "2021-09-20 15:26:26 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-09-12 17:47:21 +0200 (Tue, 12 Sep 2017)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_name( "D-Link 850L Firmware B1 Admin Password Disclosure Vulnerability (remote)" );
	script_category( ACT_ATTACK );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_xref( name: "URL", value: "https://packetstormsecurity.com/files/144056/dlink850l-xssexecxsrf.txt" );
	script_xref( name: "URL", value: "http://securityaffairs.co/wordpress/62937/hacking/d-link-dir-850l-zero-day.html" );
	script_tag( name: "summary", value: "D-Link 850L Firmware B1 is vulnerable to Admin Disclosure Vulnerability." );
	script_tag( name: "vuldetect", value: "Send crafted HTTP POST requests and check the answers." );
	script_tag( name: "insight", value: "The webpage ip_of_router/register_send.php doesn't check the authentication of the user, thus an attacker can abuse this webpage to
  gain control of the device. This webpage is used to register the device to the myDlink cloud infrastructure." );
	script_tag( name: "impact", value: "Remote attacker can retrieve the admin password and gain full access." );
	script_tag( name: "affected", value: "D-Link DIR 850L Rev B1." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year since the disclosure
  of this vulnerability. Likely none will be provided anymore. General solution options are to upgrade to a newer
  release, disable respective features, remove the product or replace the product by another one." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_tag( name: "qod_type", value: "remote_analysis" );
	script_tag( name: "deprecated", value: TRUE );
	exit( 0 );
}
exit( 66 );

