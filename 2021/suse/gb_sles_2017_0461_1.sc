if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2017.0461.1" );
	script_cve_id( "CVE-2016-2108", "CVE-2016-7056", "CVE-2016-8610", "CVE-2017-3731" );
	script_tag( name: "creation_date", value: "2021-04-19 00:00:00 +0000 (Mon, 19 Apr 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-01-05 02:30:00 +0000 (Fri, 05 Jan 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2017:0461-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2017:0461-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2017/suse-su-20170461-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openssl' package(s) announced via the SUSE-SU-2017:0461-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openssl fixes the following issues contained in the OpenSSL Security Advisory [26 Jan 2017] (bsc#1021641)
Security issues fixed:
- CVE-2016-7056: A local ECSDA P-256 timing attack that might have allowed
 key recovery was fixed (bsc#1019334)
- CVE-2016-8610: A remote denial of service in SSL alert handling was
 fixed (bsc#1005878)
- CVE-2016-2108: Added a missing commit for CVE-2016-2108, fixing the
 negative zero handling in the ASN.1 decoder (bsc#1004499)
- CVE-2017-3731: Truncated packet could crash via OOB read (bsc#1022085,
 CVE-2017-3731)
- Degrade the 3DES cipher to MEDIUM in SSLv2 (bsc#1001912)
Bugs fixed:
- fix crash in openssl speed (bsc#1000677)
- fix ca-bundle path (bsc#1022271)" );
	script_tag( name: "affected", value: "'openssl' package(s) on SUSE Linux Enterprise Desktop 12-SP1, SUSE Linux Enterprise Server 12-SP1, SUSE Linux Enterprise Software Development Kit 12-SP1." );
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
if(release == "SLES12.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0", rpm: "libopenssl1_0_0~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-32bit", rpm: "libopenssl1_0_0-32bit~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo", rpm: "libopenssl1_0_0-debuginfo~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-debuginfo-32bit", rpm: "libopenssl1_0_0-debuginfo-32bit~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-hmac", rpm: "libopenssl1_0_0-hmac~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libopenssl1_0_0-hmac-32bit", rpm: "libopenssl1_0_0-hmac-32bit~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl", rpm: "openssl~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debuginfo", rpm: "openssl-debuginfo~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-debugsource", rpm: "openssl-debugsource~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openssl-doc", rpm: "openssl-doc~1.0.1i~54.5.1", rls: "SLES12.0SP1" ) )){
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

