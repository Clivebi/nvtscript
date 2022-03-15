if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120681" );
	script_version( "2021-02-05T10:24:35+0000" );
	script_tag( name: "creation_date", value: "2016-05-09 14:11:56 +0300 (Mon, 09 May 2016)" );
	script_tag( name: "last_modification", value: "2021-02-05 10:24:35 +0000 (Fri, 05 Feb 2021)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2016-691)" );
	script_tag( name: "insight", value: "Multiple flaws were found in the MIT Kerberos krb5 library. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update krb5 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2016-691.html" );
	script_cve_id( "CVE-2015-8629", "CVE-2015-8630", "CVE-2015-8631" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "krb5-debuginfo", rpm: "krb5-debuginfo~1.13.2~12.40.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-libs", rpm: "krb5-libs~1.13.2~12.40.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-devel", rpm: "krb5-devel~1.13.2~12.40.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-pkinit-openssl", rpm: "krb5-pkinit-openssl~1.13.2~12.40.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-workstation", rpm: "krb5-workstation~1.13.2~12.40.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server", rpm: "krb5-server~1.13.2~12.40.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5-server-ldap", rpm: "krb5-server-ldap~1.13.2~12.40.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "krb5", rpm: "krb5~1.13.2~12.40.amzn1", rls: "AMAZON" ) )){
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

