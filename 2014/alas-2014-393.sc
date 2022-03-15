if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120247" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:21:18 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-393)" );
	script_tag( name: "insight", value: "Multiple flaws were found in PHP. Please see the references for more information." );
	script_tag( name: "solution", value: "Run yum update php to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-393.html" );
	script_cve_id( "CVE-2014-0237", "CVE-2014-3981", "CVE-2013-6712", "CVE-2014-4049", "CVE-2014-0207", "CVE-2014-3515", "CVE-2014-0238" );
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
	if(!isnull( res = isrpmvuln( pkg: "php-enchant", rpm: "php-enchant~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php", rpm: "php~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-devel", rpm: "php-devel~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-xmlrpc", rpm: "php-xmlrpc~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-bcmath", rpm: "php-bcmath~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-fpm", rpm: "php-fpm~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-tidy", rpm: "php-tidy~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-embedded", rpm: "php-embedded~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-mysql", rpm: "php-mysql~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-xml", rpm: "php-xml~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-mcrypt", rpm: "php-mcrypt~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-snmp", rpm: "php-snmp~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-pspell", rpm: "php-pspell~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-mssql", rpm: "php-mssql~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ldap", rpm: "php-ldap~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-intl", rpm: "php-intl~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-odbc", rpm: "php-odbc~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-debuginfo", rpm: "php-debuginfo~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-pdo", rpm: "php-pdo~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-mbstring", rpm: "php-mbstring~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-gd", rpm: "php-gd~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-recode", rpm: "php-recode~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-pgsql", rpm: "php-pgsql~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-imap", rpm: "php-imap~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-cli", rpm: "php-cli~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-soap", rpm: "php-soap~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-process", rpm: "php-process~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-dba", rpm: "php-dba~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-common", rpm: "php-common~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-mysqlnd", rpm: "php-mysqlnd~5.3.29~1.7.amzn1", rls: "AMAZON" ) )){
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

