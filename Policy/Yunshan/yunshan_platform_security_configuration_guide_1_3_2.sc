if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.150682" );
	script_version( "2021-09-16T08:25:11+0000" );
	script_tag( name: "last_modification", value: "2021-09-16 08:25:11 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-06-17 11:41:38 +0000 (Thu, 17 Jun 2021)" );
	script_tag( name: "cvss_base", value: "0.0" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:H/Au:S/C:N/I:N/A:N" );
	script_tag( name: "qod", value: "97" );
	script_name( "Huawei Data Communication: SSL is configured with an insecure algorithm" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Policy" );
	script_dependencies( "compliance_tests.sc", "gb_huawei_vrp_network_device_consolidation.sc" );
	script_mandatory_keys( "Compliance/Launch", "huawei/vrp/yunshan/detected" );
	script_tag( name: "summary", value: "If the cipher-suite-list command contains insecure algorithms,
  the service that references this rule has security risks." );
	exit( 0 );
}
require("policy_functions.inc.sc");
require("ssh_func.inc.sc");
cmd = "display current-configuration configuration ssl";
title = "SSL is configured with an insecure algorithm";
solution = "Delete the configuration and use the default cipher suite. Alternatively, you can
configure only the security algorithm.";
test_type = "SSH_Cmd";
default = "If the cipher-suite-list configuration exists, none of following algorithm is allowed:
tls12_ck_dhe_dss_aes_128_cbc_sha
tls12_ck_dhe_dss_aes_128_cbc_sha256
tls12_ck_dhe_dss_aes_256_cbc_sha
tls12_ck_dhe_dss_aes_256_cbc_sha256
tls12_ck_dhe_rsa_aes_128_cbc_sha
tls12_ck_dhe_rsa_aes_128_cbc_sha256
tls12_ck_dhe_rsa_aes_256_cbc_sha
tls12_ck_dhe_rsa_aes_256_cbc_sha256
tls12_ck_rsa_aes_128_cbc_sha
tls12_ck_rsa_aes_128_cbc_sha256
tls12_ck_rsa_aes_256_cbc_sha
tls12_ck_rsa_aes_256_cbc_sha256
tls1_ck_dhe_dss_with_aes_128_sha
tls1_ck_dhe_dss_with_aes_256_sha
tls1_ck_dhe_rsa_with_aes_128_sha
tls1_ck_dhe_rsa_with_aes_256_sha
tls1_ck_rsa_with_aes_128_sha
tls1_ck_rsa_with_aes_256_sha";
if( !get_kb_item( "login/SSH/success" ) || !sock = ssh_login_or_reuse_connection() ){
	compliant = "incomplete";
	value = "error";
	comment = "No SSH connection to host";
}
else {
	if( !value = ssh_cmd( socket: sock, cmd: cmd, return_errors: FALSE, pty: TRUE, nosh: TRUE, timeout: 20, retry: 10, force_reconnect: TRUE, clear_buffer: TRUE ) ){
		compliant = "incomplete";
		value = "error";
		comment = "Command '" + cmd + "' did not return anything";
	}
	else {
		if( IsMatchRegexp( value, "-----More----" ) ){
			compliant = "incomplete";
			value = "error";
			comment = "The return was truncated. Please set screen-length for this user-interface vty to 0.";
		}
		else {
			if( !IsMatchRegexp( value, "cipher-suite-list" ) ){
				compliant = "yes";
			}
			else {
				weak_ciphers = make_list( "tls12_ck_dhe_dss_aes_128_cbc_sha",
					 "tls12_ck_dhe_dss_aes_128_cbc_sha256",
					 "tls12_ck_dhe_dss_aes_256_cbc_sha",
					 "tls12_ck_dhe_dss_aes_256_cbc_sha256",
					 "tls12_ck_dhe_rsa_aes_128_cbc_sha",
					 "tls12_ck_dhe_rsa_aes_128_cbc_sha256",
					 "tls12_ck_dhe_rsa_aes_256_cbc_sha",
					 "tls12_ck_dhe_rsa_aes_256_cbc_sha256",
					 "tls12_ck_rsa_aes_128_cbc_sha",
					 "tls12_ck_rsa_aes_128_cbc_sha256",
					 "tls12_ck_rsa_aes_256_cbc_sha",
					 "tls12_ck_rsa_aes_256_cbc_sha256",
					 "tls1_ck_dhe_dss_with_aes_128_sha",
					 "tls1_ck_dhe_dss_with_aes_256_sha",
					 "tls1_ck_dhe_rsa_with_aes_128_sha",
					 "tls1_ck_dhe_rsa_with_aes_256_sha",
					 "tls1_ck_rsa_with_aes_128_sha",
					 "tls1_ck_rsa_with_aes_256_sha" );
				cipher_line = egrep( string: value, pattern: "cipher-suite-list" );
				if(cipher_line){
					for cipher in weak_ciphers {
						if(ContainsString( cipher_line, cipher )){
							compliant = "no";
						}
					}
				}
				if(!compliant){
					compliant = "yes";
				}
			}
		}
	}
}
policy_reporting( result: value, default: default, compliant: compliant, fixtext: solution, type: test_type, test: cmd, info: comment );
policy_set_kbs( type: test_type, cmd: cmd, default: default, solution: solution, title: title, value: value, compliant: compliant );
exit( 0 );

