if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.1104.1" );
	script_cve_id( "CVE-2014-3505", "CVE-2014-3506", "CVE-2014-3507", "CVE-2014-3508", "CVE-2014-3510" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:16 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-01-07 03:00:00 +0000 (Sat, 07 Jan 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:1104-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP3|SLES10\\.0SP4|SLES11\\.0SP1|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:1104-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20141104-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'OpenSSL' package(s) announced via the SUSE-SU-2014:1104-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This OpenSSL update fixes the following security issues:

 * bnc#890764: Information leak in pretty printing functions.
 (CVE-2014-3508)
 * bnc#890767: Double Free when processing DTLS packets. (CVE-2014-3505)
 * bnc#890768: DTLS memory exhaustion. (CVE-2014-3506)
 * bnc#890769: DTLS memory leak from zero-length fragments.
 (CVE-2014-3507)
 * bnc#890770: DTLS anonymous EC(DH) denial of service. (CVE-2014-3510)

Security Issues:

 * CVE-2014-3508
 * CVE-2014-3505
 * CVE-2014-3506
 * CVE-2014-3507
 * CVE-2014-3510" );
	script_tag( name: "affected", value: "'OpenSSL' package(s) on SUSE Linux Enterprise Server 10 SP3, SUSE Linux Enterprise Server 10 SP4, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 11 SP2." );
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
if(release == "SLES10.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8a~18.45.79.3", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-32bit", rpm: "openssl-32bit~0.9.8a~18.45.79.3", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~0.9.8a~18.45.79.3", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel-32bit", rpm: "openssl-devel-32bit~0.9.8a~18.45.79.3", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8a~18.45.79.3", rls: "SLES10.0SP3" ) )){
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8a~18.84.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-32bit", rpm: "openssl-32bit~0.9.8a~18.84.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel", rpm: "openssl-devel~0.9.8a~18.84.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-devel-32bit", rpm: "openssl-devel-32bit~0.9.8a~18.84.5", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8a~18.84.5", rls: "SLES10.0SP4" ) )){
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~0.62.3", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~0.62.3", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac", rpm: "libopenssl0_9_8-hmac~0.9.8j~0.62.3", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac-32bit", rpm: "libopenssl0_9_8-hmac-32bit~0.9.8j~0.62.3", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8j~0.62.3", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8j~0.62.3", rls: "SLES11.0SP1" ) )){
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8", rpm: "libopenssl0_9_8~0.9.8j~0.62.3", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-32bit", rpm: "libopenssl0_9_8-32bit~0.9.8j~0.62.3", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac", rpm: "libopenssl0_9_8-hmac~0.9.8j~0.62.3", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl0_9_8-hmac-32bit", rpm: "libopenssl0_9_8-hmac-32bit~0.9.8j~0.62.3", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~0.9.8j~0.62.3", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~0.9.8j~0.62.3", rls: "SLES11.0SP2" ) )){
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

