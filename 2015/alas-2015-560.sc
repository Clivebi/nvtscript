if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120106" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:17:35 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2015-560)" );
	script_tag( name: "insight", value: "Upstream reported a vulnerability in the Zend\\Mail component in Zend Framework 2, specifically in how it handles headers. Headers are not correctly filtered for newlines, allowing the ability to send additional, unrelated headers and to bypass additional headers by emitting the header/body separator sequence." );
	script_tag( name: "solution", value: "Run yum update php-ZendFramework to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2015-560.html" );
	script_cve_id( "CVE-2015-3154" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
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
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-extras", rpm: "php-ZendFramework-extras~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-demos", rpm: "php-ZendFramework-demos~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Db-Adapter-Pdo-Mssql", rpm: "php-ZendFramework-Db-Adapter-Pdo-Mssql~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Pdf", rpm: "php-ZendFramework-Pdf~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Cache-Backend-Libmemcached", rpm: "php-ZendFramework-Cache-Backend-Libmemcached~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Cache-Backend-Memcached", rpm: "php-ZendFramework-Cache-Backend-Memcached~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Serializer-Adapter-Igbinary", rpm: "php-ZendFramework-Serializer-Adapter-Igbinary~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Db-Adapter-Pdo-Pgsql", rpm: "php-ZendFramework-Db-Adapter-Pdo-Pgsql~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Db-Adapter-Pdo", rpm: "php-ZendFramework-Db-Adapter-Pdo~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Captcha", rpm: "php-ZendFramework-Captcha~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Ldap", rpm: "php-ZendFramework-Ldap~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Search-Lucene", rpm: "php-ZendFramework-Search-Lucene~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Dojo", rpm: "php-ZendFramework-Dojo~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Db-Adapter-Mysqli", rpm: "php-ZendFramework-Db-Adapter-Mysqli~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Auth-Adapter-Ldap", rpm: "php-ZendFramework-Auth-Adapter-Ldap~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Feed", rpm: "php-ZendFramework-Feed~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-full", rpm: "php-ZendFramework-full~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Cache-Backend-Apc", rpm: "php-ZendFramework-Cache-Backend-Apc~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Soap", rpm: "php-ZendFramework-Soap~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework", rpm: "php-ZendFramework~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Services", rpm: "php-ZendFramework-Services~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework-Db-Adapter-Pdo-Mysql", rpm: "php-ZendFramework-Db-Adapter-Pdo-Mysql~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "php-ZendFramework", rpm: "php-ZendFramework~1.12.13~1.11.amzn1", rls: "AMAZON" ) )){
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

