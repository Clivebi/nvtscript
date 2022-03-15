if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2021.2913.1" );
	script_cve_id( "CVE-2021-20298", "CVE-2021-20299", "CVE-2021-20300", "CVE-2021-20302", "CVE-2021-20303", "CVE-2021-20304", "CVE-2021-3476" );
	script_tag( name: "creation_date", value: "2021-09-03 02:21:39 +0000 (Fri, 03 Sep 2021)" );
	script_version( "2021-09-03T02:21:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-03 02:21:39 +0000 (Fri, 03 Sep 2021)" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:L" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-11 04:15:00 +0000 (Sun, 11 Jul 2021)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2021:2913-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES12\\.0SP2|SLES12\\.0SP3|SLES12\\.0SP4|SLES12\\.0SP5)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2021:2913-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2021/suse-su-20212913-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'openexr' package(s) announced via the SUSE-SU-2021:2913-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for openexr fixes the following issues:

CVE-2021-20298 [bsc#1188460]: Fixed Out-of-memory in B44Compressor

CVE-2021-20299 [bsc#1188459]: Fixed Null-dereference READ in
 Imf_2_5:Header:operator

CVE-2021-20300 [bsc#1188458]: Fixed Integer-overflow in
 Imf_2_5:hufUncompress

CVE-2021-20302 [bsc#1188462]: Fixed Floating-point-exception in
 Imf_2_5:precalculateTileInfot

CVE-2021-20303 [bsc#1188457]: Fixed Heap-buffer-overflow in
 Imf_2_5::copyIntoFrameBuffer

CVE-2021-20304 [bsc#1188461]: Fixed Undefined-shift in Imf_2_5:hufDecode" );
	script_tag( name: "affected", value: "'openexr' package(s) on HPE Helion Openstack 8, SUSE Linux Enterprise Server 12-SP2, SUSE Linux Enterprise Server 12-SP3, SUSE Linux Enterprise Server 12-SP4, SUSE Linux Enterprise Server 12-SP5, SUSE Linux Enterprise Server for SAP 12-SP3, SUSE Linux Enterprise Server for SAP 12-SP4, SUSE Linux Enterprise Software Development Kit 12-SP5, SUSE Linux Enterprise Workstation Extension 12-SP5, SUSE OpenStack Cloud 8, SUSE OpenStack Cloud 9, SUSE OpenStack Cloud Crowbar 8, SUSE OpenStack Cloud Crowbar 9." );
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
if(release == "SLES12.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-Imf_2_1-21", rpm: "libIlmImf-Imf_2_1-21~2.1.0~6.37.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-Imf_2_1-21-debuginfo", rpm: "libIlmImf-Imf_2_1-21-debuginfo~2.1.0~6.37.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr", rpm: "openexr~2.1.0~6.37.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debuginfo", rpm: "openexr-debuginfo~2.1.0~6.37.1", rls: "SLES12.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debugsource", rpm: "openexr-debugsource~2.1.0~6.37.1", rls: "SLES12.0SP2" ) )){
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
if(release == "SLES12.0SP3"){
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-Imf_2_1-21", rpm: "libIlmImf-Imf_2_1-21~2.1.0~6.37.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-Imf_2_1-21-debuginfo", rpm: "libIlmImf-Imf_2_1-21-debuginfo~2.1.0~6.37.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr", rpm: "openexr~2.1.0~6.37.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debuginfo", rpm: "openexr-debuginfo~2.1.0~6.37.1", rls: "SLES12.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debugsource", rpm: "openexr-debugsource~2.1.0~6.37.1", rls: "SLES12.0SP3" ) )){
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
if(release == "SLES12.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-Imf_2_1-21", rpm: "libIlmImf-Imf_2_1-21~2.1.0~6.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-Imf_2_1-21-debuginfo", rpm: "libIlmImf-Imf_2_1-21-debuginfo~2.1.0~6.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr", rpm: "openexr~2.1.0~6.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debuginfo", rpm: "openexr-debuginfo~2.1.0~6.37.1", rls: "SLES12.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debugsource", rpm: "openexr-debugsource~2.1.0~6.37.1", rls: "SLES12.0SP4" ) )){
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
if(release == "SLES12.0SP5"){
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-Imf_2_1-21", rpm: "libIlmImf-Imf_2_1-21~2.1.0~6.37.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libIlmImf-Imf_2_1-21-debuginfo", rpm: "libIlmImf-Imf_2_1-21-debuginfo~2.1.0~6.37.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr", rpm: "openexr~2.1.0~6.37.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debuginfo", rpm: "openexr-debuginfo~2.1.0~6.37.1", rls: "SLES12.0SP5" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "openexr-debugsource", rpm: "openexr-debugsource~2.1.0~6.37.1", rls: "SLES12.0SP5" ) )){
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

