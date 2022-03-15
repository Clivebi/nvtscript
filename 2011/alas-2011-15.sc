if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120489" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 11:26:55 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2011-15)" );
	script_tag( name: "insight", value: "Multiple NULL pointer dereference and assertion failure flaws were found in the MIT Kerberos KDC when it was configured to use an LDAP (Lightweight Directory Access Protocol) or Berkeley Database (Berkeley DB) back end. A remote attacker could use these flaws to crash the KDC. (CVE-2011-1527, CVE-2011-1528, CVE-2011-1529 )" );
	script_tag( name: "solution", value: "Run yum update krb5 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2011-15.html" );
	script_cve_id( "CVE-2011-1527" );
	script_tag( name: "cvss_base", value: "7.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:C" );
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
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.9~9.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server-ldap", rpm: "krb5-server-ldap~1.9~9.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.9~9.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-pkinit-openssl", rpm: "krb5-pkinit-openssl~1.9~9.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-libs", rpm: "krb5-libs~1.9~9.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-workstation", rpm: "krb5-workstation~1.9~9.19.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-debuginfo", rpm: "krb5-debuginfo~1.9~9.19.amzn1", rls: "AMAZON" ) )){
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

