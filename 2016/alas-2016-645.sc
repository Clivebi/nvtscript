if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120635" );
	script_version( "2021-09-20T10:01:48+0000" );
	script_tag( name: "creation_date", value: "2016-02-11 07:16:44 +0200 (Thu, 11 Feb 2016)" );
	script_tag( name: "last_modification", value: "2021-09-20 10:01:48 +0000 (Mon, 20 Sep 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-645)" );
	script_tag( name: "insight", value: "A flaw was found in the way TLS 1.2 could use the MD5 hash function for signing ServerKeyExchange and Client Authentication packets during a TLS handshake. A man-in-the-middle attacker able to force a TLS connection to use the MD5 hash function could use this flaw to conduct collision attacks to impersonate a TLS server or an authenticated TLS client. (CVE-2015-7575 )" );
	script_tag( name: "solution", value: "Run yum update nss to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-645.html" );
	script_cve_id( "CVE-2015-7575" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/amazon_linux", "ssh/login/release" );
	script_category( ACT_GATHER_INFO );
	script_tag( name: "summary", value: "The remote host is missing an update announced via the referenced Security Advisory." );
	script_copyright( "Copyright (C) 2016 Eero Volotinen" );
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
	if(!isnull( res = isrpmvuln( pkg: "nss-debuginfo", rpm: "nss-debuginfo~3.19.1~19.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-pkcs11-devel", rpm: "nss-pkcs11-devel~3.19.1~19.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-sysinit", rpm: "nss-sysinit~3.19.1~19.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-tools", rpm: "nss-tools~3.19.1~19.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss", rpm: "nss~3.19.1~19.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "nss-devel", rpm: "nss-devel~3.19.1~19.75.amzn1", rls: "AMAZON" ) )){
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

