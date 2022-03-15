if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2020.3762.1" );
	script_cve_id( "CVE-2020-1971" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-20 23:15:00 +0000 (Tue, 20 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2020:3762-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES15\\.0SP1|SLES15\\.0SP2|SLES15\\.0SP3|SLES15\\.0)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2020:3762-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2020/suse-su-20203762-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl-1_0_0' package(s) announced via the SUSE-SU-2020:3762-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssl-1_0_0 fixes the following issues:

CVE-2020-1971: Fixed a null pointer dereference in EDIPARTYNAME
 (bsc#1179491).

Initialized dh->nid to NID_undef in DH_new_method() (bsc#1177673).

Fixed a test failure in apache_ssl in fips mode (bsc#1177793).

Renamed BN_get_rfc3526_prime_* functions back to get_rfc3526_prime_*
 (bsc#1177575).

Restored private key check in EC_KEY_check_key (bsc#1177479).

Added shared secret KAT to FIPS DH selftest (bsc#1176029).

Included ECDH/DH Requirements from SP800-56Arev3 (bsc#1176029).

Used SHA-2 in the RSA pairwise consistency check (bsc#1155346)" );
	script_tag( name: "affected", value: "'openssl-1_0_0' package(s) on SUSE Enterprise Storage 6, SUSE Linux Enterprise Module for Legacy Software 15-SP1, SUSE Linux Enterprise Module for Legacy Software 15-SP2, SUSE Linux Enterprise Module for Legacy Software 15-SP3, SUSE Linux Enterprise Server 15, SUSE Linux Enterprise Server for SAP 15." );
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
if(release == "SLES15.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_0_0-devel", rpm: "libopenssl-1_0_0-devel~1.0.2p~3.34.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.2p~3.34.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.2p~3.34.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0", rpm: "openssl-1_0_0~1.0.2p~3.34.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debuginfo", rpm: "openssl-1_0_0-debuginfo~1.0.2p~3.34.1", rls: "SLES15.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debugsource", rpm: "openssl-1_0_0-debugsource~1.0.2p~3.34.1", rls: "SLES15.0SP1" ) )){
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
if(release == "SLES15.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_0_0-devel", rpm: "libopenssl-1_0_0-devel~1.0.2p~3.34.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.2p~3.34.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.2p~3.34.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0", rpm: "openssl-1_0_0~1.0.2p~3.34.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debuginfo", rpm: "openssl-1_0_0-debuginfo~1.0.2p~3.34.1", rls: "SLES15.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debugsource", rpm: "openssl-1_0_0-debugsource~1.0.2p~3.34.1", rls: "SLES15.0SP2" ) )){
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
if(release == "SLES15.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_0_0-devel", rpm: "libopenssl-1_0_0-devel~1.0.2p~3.34.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl10", rpm: "libopenssl10~1.0.2p~3.34.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl10-debuginfo", rpm: "libopenssl10-debuginfo~1.0.2p~3.34.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.2p~3.34.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.2p~3.34.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0", rpm: "openssl-1_0_0~1.0.2p~3.34.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debuginfo", rpm: "openssl-1_0_0-debuginfo~1.0.2p~3.34.1", rls: "SLES15.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debugsource", rpm: "openssl-1_0_0-debugsource~1.0.2p~3.34.1", rls: "SLES15.0SP3" ) )){
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
if(release == "SLES15.0"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl-1_0_0-devel", rpm: "libopenssl-1_0_0-devel~1.0.2p~3.34.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.2p~3.34.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.2p~3.34.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0", rpm: "openssl-1_0_0~1.0.2p~3.34.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debuginfo", rpm: "openssl-1_0_0-debuginfo~1.0.2p~3.34.1", rls: "SLES15.0" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-1_0_0-debugsource", rpm: "openssl-1_0_0-debugsource~1.0.2p~3.34.1", rls: "SLES15.0" ) )){
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

