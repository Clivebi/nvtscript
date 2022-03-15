if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120095" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:17:18 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2013-192)" );
	script_tag( name: "insight", value: "A buffer overflow flaw was found in Openswan. If Opportunistic Encryption were enabled (oe=yes in /etc/ipsec.conf) and an RSA key configured, an attacker able to cause a system to perform a DNS lookup for an attacker-controlled domain containing malicious records (such as by sending an email that triggers a DKIM or SPF DNS record lookup) could cause Openswan's pluto IKE daemon to crash or, potentially, execute arbitrary code with root privileges. With oe=yes but no RSA key configured, the issue can only be triggered by attackers on the local network who can control the reverse DNS entry of the target system. Opportunistic Encryption is disabled by default. (CVE-2013-2053 )" );
	script_tag( name: "solution", value: "Run yum update openswan to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2013-192.html" );
	script_cve_id( "CVE-2013-2053" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2015 Eero Volotinen" );
	script_family( "Amazon Linux Local Security Checks" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
report = "";
if(release == "AMAZON"){
	if(!isnull( res = isrpmvuln( pkg: "openswan-doc", rpm: "openswan-doc~2.6.37~2.16.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openswan-debuginfo", rpm: "openswan-debuginfo~2.6.37~2.16.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openswan", rpm: "openswan~2.6.37~2.16.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if( report != "" ){
		security_message( data: report );
	}
	else {
		if(__pkg_match){
			exit( 99 );
		}
	}
	exit( 0 );
}
exit( 0 );

