if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120520" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-10-22 08:25:44 +0300 (Thu, 22 Oct 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-601)" );
	script_tag( name: "insight", value: "Multiple flaws were found in PHP. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update php56 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-601.html" );
	script_cve_id( "CVE-2015-7803", "CVE-2015-6834", "CVE-2015-6835", "CVE-2015-7804" );
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
	if(!isnull( res = isrpmvuln( pkg: "php56-xmlrpc", rpm: "php56-xmlrpc~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-xml", rpm: "php56-xml~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-odbc", rpm: "php56-odbc~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-imap", rpm: "php56-imap~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-pdo", rpm: "php56-pdo~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-debuginfo", rpm: "php56-debuginfo~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-gmp", rpm: "php56-gmp~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-mcrypt", rpm: "php56-mcrypt~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-dba", rpm: "php56-dba~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-tidy", rpm: "php56-tidy~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-enchant", rpm: "php56-enchant~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-opcache", rpm: "php56-opcache~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-common", rpm: "php56-common~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-devel", rpm: "php56-devel~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-fpm", rpm: "php56-fpm~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-mssql", rpm: "php56-mssql~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-pspell", rpm: "php56-pspell~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-snmp", rpm: "php56-snmp~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-process", rpm: "php56-process~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-cli", rpm: "php56-cli~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-mysqlnd", rpm: "php56-mysqlnd~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-ldap", rpm: "php56-ldap~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-gd", rpm: "php56-gd~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-intl", rpm: "php56-intl~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-embedded", rpm: "php56-embedded~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-dbg", rpm: "php56-dbg~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56", rpm: "php56~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-bcmath", rpm: "php56-bcmath~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-soap", rpm: "php56-soap~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-pgsql", rpm: "php56-pgsql~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-recode", rpm: "php56-recode~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php56-mbstring", rpm: "php56-mbstring~5.6.14~1.119.amzn1", rls: "AMAZON" ) )){
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

