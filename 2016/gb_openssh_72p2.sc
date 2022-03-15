CPE = "cpe:/a:openbsd:openssh";
if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105581" );
	script_version( "2020-03-06T09:16:18+0000" );
	script_cve_id( "CVE-2016-3115" );
	script_tag( name: "cvss_base", value: "5.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:P/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-03-06 09:16:18 +0000 (Fri, 06 Mar 2020)" );
	script_tag( name: "creation_date", value: "2016-03-21 11:45:13 +0100 (Mon, 21 Mar 2016)" );
	script_name( "OpenSSH <= 7.2p1 - Xauth Injection" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_dependencies( "gb_openssh_consolidation.sc" );
	script_mandatory_keys( "openssh/detected" );
	script_xref( name: "URL", value: "http://www.openssh.com/txt/release-7.2p2" );
	script_tag( name: "summary", value: "openssh xauth command injection may lead to forced-command and
  /bin/false bypass" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "An authenticated user may inject arbitrary xauth commands by sending an
  x11 channel request that includes a newline character in the x11 cookie. The newline acts as a command
  separator to the xauth binary. This attack requires the server to have 'X11Forwarding yes' enabled.
  Disabling it, mitigates this vector." );
	script_tag( name: "impact", value: "By injecting xauth commands one gains limited* read/write arbitrary files,
  information leakage or xauth-connect capabilities." );
	script_tag( name: "affected", value: "OpenSSH versions before 7.2p2." );
	script_tag( name: "solution", value: "Upgrade to OpenSSH version 7.2p2 or later." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "remote_banner_unreliable" );
	exit( 0 );
}
require("version_func.inc.sc");
require("host_details.inc.sc");
if(isnull( port = get_app_port( cpe: CPE ) )){
	exit( 0 );
}
if(!infos = get_app_version_and_location( cpe: CPE, port: port, exit_no_version: TRUE )){
	exit( 0 );
}
vers = infos["version"];
path = infos["location"];
if(IsMatchRegexp( vers, "^[0-6]\\." ) || IsMatchRegexp( vers, "^7\\.[01]($|[^0-9])" ) || IsMatchRegexp( vers, "^7.2($|p1)" )){
	report = report_fixed_ver( installed_version: vers, fixed_version: "7.2p2", install_path: path );
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

