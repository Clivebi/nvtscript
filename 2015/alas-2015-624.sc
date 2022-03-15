if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120614" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-12-15 02:51:26 +0200 (Tue, 15 Dec 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-624)" );
	script_tag( name: "insight", value: "A flaw was found in the OTP kdcpreauth module of MIT Kerberos. A remote attacker could use this flaw to bypass the requires_preauth flag on a client principal and obtain a ciphertext encrypted in the principal's long-term key. This ciphertext could be used to conduct an off-line dictionary attack against the user's password.It was found that the krb5_read_message() function of MIT Kerberos did not correctly sanitize input, and could create invalid krb5_data objects. A remote, unauthenticated attacker could use this flaw to crash a Kerberos child process via a specially crafted request." );
	script_tag( name: "solution", value: "Run yum update krb5 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-624.html" );
	script_cve_id( "CVE-2015-2694", "CVE-2014-5355" );
	script_tag( name: "cvss_base", value: "5.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:N" );
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
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.13.2~10.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-libs", rpm: "krb5-libs~1.13.2~10.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-debuginfo", rpm: "krb5-debuginfo~1.13.2~10.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-workstation", rpm: "krb5-workstation~1.13.2~10.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server-ldap", rpm: "krb5-server-ldap~1.13.2~10.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.13.2~10.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-pkinit-openssl", rpm: "krb5-pkinit-openssl~1.13.2~10.39.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.13.2~10.39.amzn1", rls: "AMAZON" ) )){
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

