if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2090.1" );
	script_cve_id( "CVE-2016-5387" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2090-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2090-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162090-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2016:2090-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for apache2 fixes the following issues:
- It used to be possible to set an arbitrary $HTTP_PROXY environment
 variable for request handlers -- like CGI scripts -- by including a
 specially crafted HTTP header in the request (CVE-2016-5387). As a
 result, these server components would potentially direct all their
 outgoing HTTP traffic through a malicious proxy server. This patch fixes
 the issue: the updated Apache server ignores such HTTP headers and never
 sets $HTTP_PROXY for sub-processes (unless a value has been explicitly
 configured by the administrator in the configuration file). (bsc#988488)
- Ignore SIGINT signal in child processes. This fixes a race condition in
 signals handling when httpd is running on foreground and the user hits
 ctrl+c. (bsc#970391)
- Don't put the backend in error state (by default) when 500/503 is
 overridden. (bsc#951692)
- Remove obsolete /usr/share/apache2/rc.apache2 sample script. (bsc#973381)" );
	script_tag( name: "affected", value: "'apache2' package(s) on SUSE Linux Enterprise Server 12, SUSE Linux Enterprise Server for SAP 12." );
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
if(release == "SLES12.0"){
	if(!isnull( res = isrpmvuln( pkg: "apache2", rpm: "apache2~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-debuginfo", rpm: "apache2-debuginfo~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-debugsource", rpm: "apache2-debugsource~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-doc", rpm: "apache2-doc~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-pages", rpm: "apache2-example-pages~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork", rpm: "apache2-prefork~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork-debuginfo", rpm: "apache2-prefork-debuginfo~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils", rpm: "apache2-utils~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils-debuginfo", rpm: "apache2-utils-debuginfo~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker", rpm: "apache2-worker~2.4.10~14.17.1", rls: "SLES12.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker-debuginfo", rpm: "apache2-worker-debuginfo~2.4.10~14.17.1", rls: "SLES12.0" ) )){
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

