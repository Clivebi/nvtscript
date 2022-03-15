if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120476" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:27:17 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2014-343)" );
	script_tag( name: "insight", value: "The BEGIN regular expression in the awk script detector in magic/Magdir/commands in file before 5.15 uses multiple wildcards with unlimited repetitions, which allows context-dependent attackers to cause a denial of service (CPU consumption) via a crafted ASCII file that triggers a large amount of backtracking, as demonstrated via a file with many newline characters." );
	script_tag( name: "solution", value: "Run yum update php54 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2014-343.html" );
	script_cve_id( "CVE-2013-7345" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "php54-tidy", rpm: "php54-tidy~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-recode", rpm: "php54-recode~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-snmp", rpm: "php54-snmp~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-mysqlnd", rpm: "php54-mysqlnd~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-cli", rpm: "php54-cli~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-gd", rpm: "php54-gd~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-pdo", rpm: "php54-pdo~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-odbc", rpm: "php54-odbc~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54", rpm: "php54~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-mcrypt", rpm: "php54-mcrypt~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-fpm", rpm: "php54-fpm~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-imap", rpm: "php54-imap~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-soap", rpm: "php54-soap~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-bcmath", rpm: "php54-bcmath~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-dba", rpm: "php54-dba~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-mbstring", rpm: "php54-mbstring~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-pgsql", rpm: "php54-pgsql~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-pspell", rpm: "php54-pspell~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-devel", rpm: "php54-devel~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-mysql", rpm: "php54-mysql~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-intl", rpm: "php54-intl~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-ldap", rpm: "php54-ldap~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-enchant", rpm: "php54-enchant~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-mssql", rpm: "php54-mssql~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-debuginfo", rpm: "php54-debuginfo~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-xml", rpm: "php54-xml~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-process", rpm: "php54-process~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-xmlrpc", rpm: "php54-xmlrpc~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-common", rpm: "php54-common~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php54-embedded", rpm: "php54-embedded~5.4.28~1.54.amzn1", rls: "AMAZON" ) )){
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

