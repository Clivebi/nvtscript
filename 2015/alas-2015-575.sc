if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120285" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:22:41 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-575)" );
	script_tag( name: "insight", value: "It was found that GnuTLS did not check activation and expiration dates of CA certificates. This could cause an application using GnuTLS to incorrectly accept a certificate as valid when its issuing CA is already expired. (CVE-2014-8155 )It was found that GnuTLS did not verify whether a hashing algorithm listed in a signature matched the hashing algorithm listed in the certificate. An attacker could create a certificate that used a different hashing algorithm than it claimed, possibly causing GnuTLS to use an insecure, disallowed hashing algorithm during certificate verification. (CVE-2015-0282 )It was discovered that GnuTLS did not check if all sections of X.509 certificates indicate the same signature algorithm. This flaw, in combination with a different flaw, could possibly lead to a bypass of the certificate signature check. (CVE-2015-0294 )" );
	script_tag( name: "solution", value: "Run yum update gnutls to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-575.html" );
	script_cve_id( "CVE-2014-8155", "CVE-2015-0282", "CVE-2015-0294" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
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
	if(!isnull( res = isrpmvuln( pkg: "gnutls", rpm: "gnutls~2.8.5~18.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-debuginfo", rpm: "gnutls-debuginfo~2.8.5~18.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-devel", rpm: "gnutls-devel~2.8.5~18.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-guile", rpm: "gnutls-guile~2.8.5~18.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "gnutls-utils", rpm: "gnutls-utils~2.8.5~18.14.amzn1", rls: "AMAZON" ) )){
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

