CPE = "cpe:/a:wordpress:wordpress";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.803884" );
	script_version( "2021-08-10T15:24:26+0000" );
	script_cve_id( "CVE-2013-2741", "CVE-2013-2742", "CVE-2013-2743", "CVE-2013-2744" );
	script_bugtraq_id( 58657, 58863, 58871, 58873 );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-10 15:24:26 +0000 (Tue, 10 Aug 2021)" );
	script_tag( name: "creation_date", value: "2013-08-29 13:44:14 +0530 (Thu, 29 Aug 2013)" );
	script_name( "WordPress Backupbuddy Multiple Vulnerabilities" );
	script_tag( name: "summary", value: "This host is installed with WordPress Backupbuddy plugin and is prone to
multiple vulnerabilities." );
	script_tag( name: "vuldetect", value: "Send a HTTP GET request and check whether it is able to disclose some
sensitive information or not." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
since the disclosure of this vulnerability. Likely none will be provided anymore.
General solution options are to upgrade to a newer release, disable respective
features, remove the product or replace the product by another one." );
	script_tag( name: "insight", value: "Multiple flaws are due to:

  - Fails to properly remove importbuddy.php during the final step of the backup
  process.

  - Improper handling of input passed via 'step' parameter to importbuddy.php script." );
	script_tag( name: "affected", value: "BackupBuddy plugin versions 1.3.4, 2.1.4, 2.2.4, 2.2.25, and 2.2.28" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to bypass password authentication
and obtain potentially sensitive information." );
	script_tag( name: "solution_type", value: "WillNotFix" );
	script_xref( name: "URL", value: "http://packetstormsecurity.com/files/120923" );
	script_xref( name: "URL", value: "http://seclists.org/fulldisclosure/2013/Mar/206" );
	script_xref( name: "URL", value: "http://exploitsdownload.com/exploit/na/backupbuddy-224-sensitive-data-exposure" );
	script_category( ACT_ATTACK );
	script_tag( name: "qod_type", value: "remote_vul" );
	script_copyright( "Copyright (C) 2013 Greenbone Networks GmbH" );
	script_family( "Web application abuses" );
	script_dependencies( "secpod_wordpress_detect_900182.sc" );
	script_mandatory_keys( "wordpress/installed" );
	script_require_ports( "Services/www", 80 );
	exit( 0 );
}
require("http_func.inc.sc");
require("http_keepalive.inc.sc");
require("host_details.inc.sc");
if(!port = get_app_port( cpe: CPE )){
	exit( 0 );
}
if(!dir = get_app_location( cpe: CPE, port: port )){
	exit( 0 );
}
req = http_get( item: NASLString( dir, "/importbuddy.php" ), port: port );
res = http_keepalive_send_recv( port: port, data: req, bodyonly: TRUE );
if(ContainsString( res, ">BackupBuddy" ) && ContainsString( res, "PluginBuddy.com<" )){
	url = dir + "/importbuddy.php?step=2";
	if(http_vuln_check( port: port, url: url, pattern: "BackupBuddy Restoration & Migration Tool", extra_check: make_list( "Migrate to new server:",
		 "Restore to same server" ) )){
		security_message( port );
		exit( 0 );
	}
}

