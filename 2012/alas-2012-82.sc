if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.120127" );
	script_version( "2020-03-13T13:19:50+0000" );
	script_tag( name: "creation_date", value: "2015-09-08 13:18:09 +0200 (Tue, 08 Sep 2015)" );
	script_tag( name: "last_modification", value: "2020-03-13 13:19:50 +0000 (Fri, 13 Mar 2020)" );
	script_name( "Amazon Linux: Security Advisory (ALAS-2012-82)" );
	script_tag( name: "insight", value: "The pg_dump utility inserted object names literally into comments in the SQL script it produces. An unprivileged database user could create an object whose name includes a newline followed by an SQL command. This SQL command might then be executed by a privileged user during later restore of the backup dump, allowing privilege escalation. (CVE-2012-0868 )When configured to do SSL certificate verification, PostgreSQL only checked the first 31 characters of the certificate's Common Name field. Depending on the configuration, this could allow an attacker to impersonate a server or a client using a certificate from a trusted Certificate Authority issued for a different name. (CVE-2012-0867 )CREATE TRIGGER did not do a permissions check on the trigger function to be called. This could possibly allow an authenticated database user to call a privileged trigger function on data of their choosing. (CVE-2012-0866 )" );
	script_tag( name: "solution", value: "Run yum update postgresql8 to update your system." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "URL", value: "https://alas.aws.amazon.com/ALAS-2012-82.html" );
	script_cve_id( "CVE-2012-0866", "CVE-2012-0867", "CVE-2012-0868" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
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
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-libs", rpm: "postgresql8-libs~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-test", rpm: "postgresql8-test~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8", rpm: "postgresql8~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-plperl", rpm: "postgresql8-plperl~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-contrib", rpm: "postgresql8-contrib~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-debuginfo", rpm: "postgresql8-debuginfo~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-pltcl", rpm: "postgresql8-pltcl~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-plpython", rpm: "postgresql8-plpython~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-docs", rpm: "postgresql8-docs~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-devel", rpm: "postgresql8-devel~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "postgresql8-server", rpm: "postgresql8-server~8.4.11~1.34.amzn1", rls: "AMAZON" ) )){
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

