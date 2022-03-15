if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.901194" );
	script_version( "2021-09-01T07:45:06+0000" );
	script_tag( name: "last_modification", value: "2021-09-01 07:45:06 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "creation_date", value: "2011-03-25 15:52:06 +0100 (Fri, 25 Mar 2011)" );
	script_cve_id( "CVE-2011-1506" );
	script_bugtraq_id( 46767 );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_name( "Kerio Products 'STARTTLS' Plaintext Command Injection Vulnerability" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2011 Greenbone Networks GmbH" );
	script_family( "General" );
	script_dependencies( "gb_kerio_mailserver_detect.sc" );
	script_mandatory_keys( "KerioMailServer/detected" );
	script_xref( name: "URL", value: "http://secunia.com/advisories/43678" );
	script_xref( name: "URL", value: "http://www.vupen.com/english/advisories/2011/0610" );
	script_tag( name: "impact", value: "Successful exploitation will allow attacker to execute arbitrary
  commands in the context of the user running the application." );
	script_tag( name: "affected", value: "Kerio MailServer versions 6.x

  Kerio Connect version 7.1.4 build 2985" );
	script_tag( name: "insight", value: "This flaw is caused by an error within the 'STARTTLS'
  implementation where the switch from plaintext to TLS is implemented below the
  application's I/O buffering layer, which could allow attackers to inject commands
  during the plaintext phase of the protocol via man-in-the-middle attacks." );
	script_tag( name: "solution", value: "No known solution was made available for at least one year
  since the disclosure of this vulnerability. Likely none will be provided anymore. General solution
  options are to upgrade to a newer release, disable respective features, remove the product or
  replace the product by another one." );
	script_tag( name: "summary", value: "The host is running Kerio Mail Server/Connect and is prone to
  plaintext command injection vulnerability." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "WillNotFix" );
	exit( 0 );
}
require("host_details.inc.sc");
require("version_func.inc.sc");
cpe_list = make_list( "cpe:/a:kerio:kerio_mailserver",
	 "cpe:/a:kerio:connect" );
if(!infos = get_app_version_and_location_from_list( cpe_list: cpe_list, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
cpe = infos["cpe"];
if( ContainsString( cpe, "cpe:/a:kerio:kerio_mailserver" ) ){
	if(IsMatchRegexp( vers, "^6\\." ) && version_in_range( version: vers, test_version: "6.0", test_version2: "6.7.3.patch1" )){
		report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
		security_message( port: 0, data: report );
		exit( 0 );
	}
}
else {
	if(ContainsString( cpe, "cpe:/a:kerio:connect" )){
		if(IsMatchRegexp( vers, "^7\\." ) && version_is_less_equal( version: vers, test_version: "7.1.4" )){
			report = report_fixed_ver( installed_version: vers, fixed_version: "None", install_path: path );
			security_message( port: 0, data: report );
			exit( 0 );
		}
	}
}
exit( 99 );

