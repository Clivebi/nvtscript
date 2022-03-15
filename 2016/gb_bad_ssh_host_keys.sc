if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.105497" );
	script_version( "2021-09-17T12:01:50+0000" );
	script_name( "Known SSH Host Key" );
	script_cve_id( "CVE-2015-6358", "CVE-2015-7255", "CVE-2015-7256", "CVE-2015-7276", "CVE-2015-8251", "CVE-2015-8260", "CVE-2009-4510", "CVE-2008-0166" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-17 12:01:50 +0000 (Fri, 17 Sep 2021)" );
	script_tag( name: "creation_date", value: "2016-01-05 13:21:28 +0100 (Tue, 05 Jan 2016)" );
	script_category( ACT_GATHER_INFO );
	script_family( "General" );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_dependencies( "ssh_proto_version.sc" );
	script_require_ports( "Services/ssh", 22 );
	script_mandatory_keys( "SSH/fingerprints/available" );
	script_xref( name: "URL", value: "https://blog.shodan.io/duplicate-ssh-keys-everywhere/" );
	script_xref( name: "URL", value: "https://www.kb.cert.org/vuls/id/566724" );
	script_xref( name: "URL", value: "http://blogs.intevation.de/thomas/hetzner-duplicate-ed25519-ssh-host-keys/" );
	script_xref( name: "URL", value: "https://www.vsecurity.com/download/advisories/20100409-2.txt" );
	script_xref( name: "URL", value: "https://wiki.debian.org/SSLkeys" );
	script_xref( name: "URL", value: "https://www.debian.org/security/2008/dsa-1571" );
	script_xref( name: "URL", value: "https://github.com/g0tmi1k/debian-ssh" );
	script_tag( name: "summary", value: "The remote host uses a default SSH host key that is shared among
  multiple installations." );
	script_tag( name: "impact", value: "An attacker could use this situation to compromise or eavesdrop
  on the SSH communication between the client and the server using a man-in-the-middle attack." );
	script_tag( name: "insight", value: "The list of known SSH host keys used by this plugin is
  gathered from various sources:

  - Top 1.000 Duplicate SSH Fingerprints on the Internet collected via the search engine Shodan in
  2015. The most common fingerprint was found to be shared among 245.000 installations where the
  least common was still present 321 times.

  - SSH host keys generated with a vulnerable OpenSSL version on Debian and derivates (CVE-2008-0166).

  - Devices of Multiple Vendors (Cisco, ZTE, ZyXEL, OpenStage, OpenScape, TANDBERG) using hardcoded
  SSH host keys (CVE-2015-6358, CVE-2015-7255, CVE-2015-7256, CVE-2015-7276, CVE-2015-8251,
  CVE-2015-8260, CVE-2009-4510)." );
	script_tag( name: "vuldetect", value: "Checks if the remote host responds with a known SSH host key." );
	script_tag( name: "solution", value: "Generate a new SSH host key." );
	script_tag( name: "solution_type", value: "Workaround" );
	script_tag( name: "qod_type", value: "remote_active" );
	exit( 0 );
}
require("bad_ssh_host_keys.inc.sc");
require("ssh_func.inc.sc");
require("misc_func.inc.sc");
require("port_service_func.inc.sc");
require("list_array_func.inc.sc");
bad_host_keys = nasl_make_list_unique( bad_host_keys );
port = ssh_get_port( default: 22 );
for algo in ssh_host_key_algos {
	host_key = get_kb_item( "SSH/" + port + "/fingerprint/" + algo );
	if(!host_key || !strlen( host_key )){
		continue;
	}
	if(in_array( search: host_key, array: bad_host_keys, part_match: FALSE )){
		_report += algo + "  " + host_key + "\n";
		bhk_found = TRUE;
	}
	if(algo == "ssh-rsa"){
		argv = make_list( "grep",
			 host_key,
			 "../bad_rsa_ssh_host_keys.txt" );
		res = pread( cmd: "grep", argv: argv, cd: FALSE );
		if(res == "\"" + host_key + "\""){
			_report += algo + "  " + host_key + "\n";
			bhk_found = TRUE;
		}
	}
	if(algo == "ssh-dss"){
		argv = make_list( "grep",
			 host_key,
			 "../bad_dsa_ssh_host_keys.txt" );
		res = pread( cmd: "grep", argv: argv, cd: FALSE );
		if(res == "\"" + host_key + "\""){
			_report += algo + "  " + host_key + "\n";
			bhk_found = TRUE;
		}
	}
}
if(bhk_found){
	report = "The following known SSH hosts key(s) were found:\n" + _report;
	security_message( port: port, data: report );
	exit( 0 );
}
exit( 99 );

