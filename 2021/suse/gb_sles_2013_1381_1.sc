if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1381.1" );
	script_cve_id( "CVE-2013-1862", "CVE-2013-1896" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.1" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:H/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-06 11:15:00 +0000 (Sun, 06 Jun 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1381-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2|SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1381-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131381-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Apache2' package(s) announced via the SUSE-SU-2013:1381-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This collective update for Apache provides the following fixes:

 *

 Make sure that input that has already arrived on the socket is not discarded during a non-blocking read (read(2)
returns 0 and errno is set to -EAGAIN). (bnc#815621)

 *

 Close the connection just before an attempted re-negotiation if data has been read with pipelining. This is done by resetting the keepalive status. (bnc#815621)

 *

 Reset the renegotiation status of a clientserver connection to RENEG_INIT to prevent falsely assumed status.
(bnc#791794)

 *

 'OPTIONS *' internal requests are intercepted by a dummy filter that kicks in for the OPTIONS method. Apple iPrint uses 'OPTIONS *' to upgrade the connection to TLS/1.0 following RFC 2817. For compatibility, check if an Upgrade request header is present and skip the filter if yes. (bnc#791794)

 *

 Sending a MERGE request against a URI handled by mod_dav_svn with the source href (sent as part of the request body as XML) pointing to a URI that is not configured for DAV will trigger a segfault. (bnc#829056,
CVE-2013-1896)

 *

 Client data written to the RewriteLog must have terminal escape sequences escaped. (bnc#829057,
CVE-2013-1862)

Security Issue references:

 * CVE-2013-1896
>
 * CVE-2013-1862
>" );
	script_tag( name: "affected", value: "'Apache2' package(s) on SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "apache2", rpm: "apache2~2.2.12~1.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-doc", rpm: "apache2-doc~2.2.12~1.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-pages", rpm: "apache2-example-pages~2.2.12~1.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork", rpm: "apache2-prefork~2.2.12~1.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils", rpm: "apache2-utils~2.2.12~1.40.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker", rpm: "apache2-worker~2.2.12~1.40.1", rls: "SLES11.0SP2" ) )){
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
if(release == "SLES11.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "apache2", rpm: "apache2~2.2.12~1.40.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-doc", rpm: "apache2-doc~2.2.12~1.40.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-example-pages", rpm: "apache2-example-pages~2.2.12~1.40.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-prefork", rpm: "apache2-prefork~2.2.12~1.40.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-utils", rpm: "apache2-utils~2.2.12~1.40.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "apache2-worker", rpm: "apache2-worker~2.2.12~1.40.1", rls: "SLES11.0SP3" ) )){
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

