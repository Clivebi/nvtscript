if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.108334" );
	script_version( "2020-08-24T15:18:35+0000" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2020-08-24 15:18:35 +0000 (Mon, 24 Aug 2020)" );
	script_tag( name: "creation_date", value: "2018-02-12 15:41:40 +0100 (Mon, 12 Feb 2018)" );
	script_name( "Coinhive JavaScript Miner Detection" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Malware" );
	script_dependencies( "webmirror.sc" );
	script_require_ports( "Services/www", 80 );
	script_mandatory_keys( "www/coinhive/detected" );
	script_xref( name: "URL", value: "https://nakedsecurity.sophos.com/2018/02/12/cryptomining-script-poisons-government-websites-what-to-do/" );
	script_tag( name: "summary", value: "This script reports if a web page of the remote host contains code from the
  Coinhive JavaScript Miner." );
	script_tag( name: "insight", value: "While the Coinhive JavaScript Miner might be deployed legitimately, it is often
  used by attackers for malicious purposes to consume unauthorized resources of a client browsing a web site.

  This script reports results of rudimentary checks for the following strings embedded into any web page of the remote host:

  - CoinHive.Anonymous

  - CoinHive.User

  - CoinHive.Token

  NOTE: There are various obfuscation technologies available to hide such JavaScript from the scanner, thus the mentioned
  'rudimentary checks' above.

  NOTE2: No vulnerability is reported if the Coinhive JavaScript is loaded from the authedmine.com domain. This JavaScript
  code only run after an explicit opt-in / agreement from the user." );
	script_tag( name: "impact", value: "If the Coinhive JavaScript Miner is started without a configured OptOut possibility for the
  client, unauthorized resources of this client will be used." );
	script_tag( name: "solution", value: "Inspect all reported web pages / URLs if the Coinhive JavaScript Miner was
  deployed legitimately and remove it if not." );
	script_tag( name: "qod_type", value: "remote_banner" );
	script_tag( name: "solution_type", value: "Mitigation" );
	exit( 0 );
}
require("http_func.inc.sc");
require("port_service_func.inc.sc");
port = http_get_port( default: 80 );
host = http_host_name( dont_add_port: TRUE );
chOptOutList = get_kb_list( "www/" + host + "/" + port + "/content/coinhive_optout" );
chNoOptOutList = get_kb_list( "www/" + host + "/" + port + "/content/coinhive_nooptout" );
chObfuscatedList = get_kb_list( "www/" + host + "/" + port + "/content/coinhive_obfuscated" );
if(!isnull( chOptOutList ) || !isnull( chNoOptOutList ) || !isnull( chObfuscatedList )){
	report += "The Coinhive JavaScript Miner was found embedded into the following pages:\n\n";
	if(chOptOutList){
		chOptOutList = sort( chOptOutList );
	}
	if(chNoOptOutList){
		chNoOptOutList = sort( chNoOptOutList );
	}
	if(chObfuscatedList){
		chObfuscatedList = sort( chObfuscatedList );
	}
	for chOptOut in chOptOutList {
		report += chOptOut + " (OptOut configured for the user)\n";
	}
	for chNoOptOut in chNoOptOutList {
		report += chNoOptOut + " (No OptOut configured for the user, might be malicious)\n";
	}
	for chObfuscated in chObfuscatedList {
		report += chObfuscated + " (Obfuscated, look out for code containing \\x73\\x70\\x6C\\x69\\x74. Very likely malicious)\n";
	}
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

