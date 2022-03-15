if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120043" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:16:03 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-338)" );
	script_tag( name: "insight", value: "Cyrus SASL 2.1.23, 2.1.26, and earlier does not properly handle when a NULL value is returned upon an error by the crypt function as implemented in glibc 2.17 and later, which allows remote attackers to cause a denial of service (thread crash and consumption) via (1) an invalid salt or, when FIPS-140 is enabled, a (2) DES or (3) MD5 encrypted password, which triggers a NULL pointer dereference." );
	script_tag( name: "solution", value: "Run yum update cyrus-sasl to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-338.html" );
	script_cve_id( "CVE-2013-4122" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-ldap", rpm: "cyrus-sasl-ldap~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-ntlm", rpm: "cyrus-sasl-ntlm~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-debuginfo", rpm: "cyrus-sasl-debuginfo~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-sql", rpm: "cyrus-sasl-sql~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-lib", rpm: "cyrus-sasl-lib~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-plain", rpm: "cyrus-sasl-plain~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-devel", rpm: "cyrus-sasl-devel~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-gssapi", rpm: "cyrus-sasl-gssapi~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl", rpm: "cyrus-sasl~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "cyrus-sasl-md5", rpm: "cyrus-sasl-md5~2.1.23~13.14.amzn1", rls: "AMAZON" ) )){
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

