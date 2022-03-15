if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120581" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:30:00 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-372)" );
	script_tag( name: "insight", value: "Multiple flaws were found in PHP. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update php55 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-372.html" );
	script_cve_id( "CVE-2014-3981", "CVE-2014-3479", "CVE-2014-0207", "CVE-2014-3515", "CVE-2014-3478", "CVE-2014-4049", "CVE-2014-3487", "CVE-2014-3480" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "php55-mysqlnd", rpm: "php55-mysqlnd~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-soap", rpm: "php55-soap~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-embedded", rpm: "php55-embedded~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-xml", rpm: "php55-xml~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-intl", rpm: "php55-intl~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-recode", rpm: "php55-recode~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-mssql", rpm: "php55-mssql~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-odbc", rpm: "php55-odbc~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-dba", rpm: "php55-dba~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-imap", rpm: "php55-imap~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-enchant", rpm: "php55-enchant~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-gmp", rpm: "php55-gmp~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55", rpm: "php55~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-debuginfo", rpm: "php55-debuginfo~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-common", rpm: "php55-common~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-bcmath", rpm: "php55-bcmath~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-xmlrpc", rpm: "php55-xmlrpc~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-tidy", rpm: "php55-tidy~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-pgsql", rpm: "php55-pgsql~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-pdo", rpm: "php55-pdo~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-ldap", rpm: "php55-ldap~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-opcache", rpm: "php55-opcache~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-snmp", rpm: "php55-snmp~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-gd", rpm: "php55-gd~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-pspell", rpm: "php55-pspell~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-mcrypt", rpm: "php55-mcrypt~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-mbstring", rpm: "php55-mbstring~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-devel", rpm: "php55-devel~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-fpm", rpm: "php55-fpm~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-cli", rpm: "php55-cli~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php55-process", rpm: "php55-process~5.5.14~1.75.amzn1", rls: "AMAZON" ) )){
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

