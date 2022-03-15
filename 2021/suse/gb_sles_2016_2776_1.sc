if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2016.2776.1" );
	script_cve_id( "CVE-2008-3522", "CVE-2015-5203", "CVE-2015-5221", "CVE-2016-1577", "CVE-2016-1867", "CVE-2016-2089", "CVE-2016-2116", "CVE-2016-8690", "CVE-2016-8691", "CVE-2016-8692", "CVE-2016-8693", "CVE-2016-8880", "CVE-2016-8881", "CVE-2016-8882", "CVE-2016-8883", "CVE-2016-8884", "CVE-2016-8885", "CVE-2016-8886", "CVE-2016-8887" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:03 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "10.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2016:2776-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2016:2776-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2016/suse-su-20162776-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'jasper' package(s) announced via the SUSE-SU-2016:2776-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for jasper fixes the following issues:
Security fixes:
- CVE-2016-8887: NULL pointer dereference in jp2_colr_destroy (jp2_cod.c)
 (bsc#1006836)
- CVE-2016-8886: memory allocation failure in jas_malloc (jas_malloc.c)
 (bsc#1006599)
- CVE-2016-8884,CVE-2016-8885: two null pointer dereferences in
 bmp_getdata (incomplete fix for CVE-2016-8690) (bsc#1007009)
- CVE-2016-8883: assert in jpc_dec_tiledecode() (bsc#1006598)
- CVE-2016-8882: segfault / null pointer access in jpc_pi_destroy
 (bsc#1006597)
- CVE-2016-8881: Heap overflow in jpc_getuint16() (bsc#1006593)
- CVE-2016-8880: Heap overflow in jpc_dec_cp_setfromcox() (bsc#1006591)
- CVE-2016-8693: Double free vulnerability in mem_close (bsc#1005242)
- CVE-2016-8691, CVE-2016-8692: Divide by zero in jpc_dec_process_siz
 (bsc#1005090)
- CVE-2016-8690: Null pointer dereference in bmp_getdata triggered by
 crafted BMP image (bsc#1005084)
- CVE-2016-2089: invalid read in the JasPer's jas_matrix_clip() function
 (bsc#963983)
- CVE-2016-1867: Out-of-bounds Read in the JasPer's jpc_pi_nextcprl()
 function (bsc#961886)
- CVE-2016-1577, CVE-2016-2116: double free vulnerability in the
 jas_iccattrval_destroy function (bsc#968373)
- CVE-2015-5221: Use-after-free (and double-free) in Jasper JPEG-200
 (bsc#942553)
- CVE-2015-5203: Double free corruption in JasPer JPEG-2000 implementation
 (bsc#941919)
- CVE-2008-3522: multiple integer overflows (bsc#392410)
- bsc#1006839: NULL pointer dereference in jp2_colr_destroy (jp2_cod.c)
 (incomplete fix for CVE-2016-8887)" );
	script_tag( name: "affected", value: "'jasper' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
if(release == "SLES11.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "libjasper", rpm: "libjasper~1.900.14~134.25.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper-32bit", rpm: "libjasper-32bit~1.900.14~134.25.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libjasper-x86", rpm: "libjasper-x86~1.900.14~134.25.1", rls: "SLES11.0SP4" ) )){
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

