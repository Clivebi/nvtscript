if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0226.1" );
	script_cve_id( "CVE-2012-2733", "CVE-2012-3546", "CVE-2012-4431", "CVE-2012-4534", "CVE-2012-5568", "CVE-2012-5885", "CVE-2012-5886", "CVE-2012-5887" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:25 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-09-19 01:34:00 +0000 (Tue, 19 Sep 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0226-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0226-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130226-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tomcat6' package(s) announced via the SUSE-SU-2013:0226-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of tomcat6 fixes the following security issues:

 * CVE-2012-4534: denial of service
 * CVE-2012-2733: tomcat: HTTP NIO connector OOM DoS via a request with large headers
 * CVE-2012-5885: tomcat: cnonce tracking weakness
 * CVE-2012-5886: tomcat: authentication caching weakness
 * CVE-2012-5887: tomcat: stale nonce weakness
 * CVE-2012-5568: tomcat: affected by slowloris DoS
 * CVE-2012-3546: tomcat: Bypass of security constraints
 * CVE-2012-4431: tomcat: bypass of CSRF prevention filter

Security Issue references:

 * CVE-2012-5885
>
 * CVE-2012-4431
>
 * CVE-2012-3546
>
 * CVE-2012-5887
>
 * CVE-2012-4534
>
 * CVE-2012-2733
>
 * CVE-2012-5886
>
 * CVE-2012-5568
>" );
	script_tag( name: "affected", value: "'tomcat6' package(s) on SUSE Linux Enterprise Server 11 SP2, SUSE Manager 1.2." );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "tomcat6", rpm: "tomcat6~6.0.18~20.35.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-admin-webapps", rpm: "tomcat6-admin-webapps~6.0.18~20.35.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-docs-webapp", rpm: "tomcat6-docs-webapp~6.0.18~20.35.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-javadoc", rpm: "tomcat6-javadoc~6.0.18~20.35.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-jsp-2_1-api", rpm: "tomcat6-jsp-2_1-api~6.0.18~20.35.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-lib", rpm: "tomcat6-lib~6.0.18~20.35.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-servlet-2_5-api", rpm: "tomcat6-servlet-2_5-api~6.0.18~20.35.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tomcat6-webapps", rpm: "tomcat6-webapps~6.0.18~20.35.40.1", rls: "SLES11.0SP2" ) )){
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

