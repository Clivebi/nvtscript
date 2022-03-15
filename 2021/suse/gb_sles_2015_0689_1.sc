if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0689.1" );
	script_cve_id( "CVE-2003-1418", "CVE-2013-5704", "CVE-2014-3581" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:P/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0689-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0689-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150689-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'apache2' package(s) announced via the SUSE-SU-2015:0689-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "The Apache2 webserver was updated to fix various issues.

The following feature was added:

 * Provide support for the tunneling of web socket connections to a
 backend websockets server. (FATE#316880)

The following security issues have been fixed:

 * CVE-2013-5704: The mod_headers module in the Apache HTTP Server
 2.2.22 allowed remote attackers to bypass 'RequestHeader unset'
 directives by placing a header in the trailer portion of data sent
 with chunked transfer coding. The fix also adds a 'MergeTrailers'
 directive to restore legacy behavior.
 * CVE-2014-3581: The cache_merge_headers_out function in
 modules/cache/cache_util.c in the mod_cache module in the Apache
 HTTP Server allowed remote attackers to cause a denial of service
 (NULL pointer dereference and application crash) via an empty HTTP
 Content-Type header.
 * CVE-2003-1418: Apache HTTP Server allowed remote attackers to obtain
 sensitive information via (1) the ETag header, which reveals the
 inode number, or (2) multipart MIME boundary, which reveals child
 process IDs (PID). We so far assumed that this not useful to
 attackers, the fix is basically just reducing potential information
 leaks.

The following bugs have been fixed:

 * Treat the 'server unavailable' condition as a transient error with
 all LDAP SDKs. (bsc#904427)
 * Fixed a segmentation fault at startup if the certs are shared across
 > 1 server_rec. (bsc#907339)" );
	script_tag( name: "affected", value: "'apache2' package(s) on SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "apache2", rpm: "apache2~2.2.12~1.51.52.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-doc", rpm: "apache2-doc~2.2.12~1.51.52.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-pages", rpm: "apache2-example-pages~2.2.12~1.51.52.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork", rpm: "apache2-prefork~2.2.12~1.51.52.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils", rpm: "apache2-utils~2.2.12~1.51.52.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker", rpm: "apache2-worker~2.2.12~1.51.52.1", rls: "SLES11.0SP3" ) )){
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

