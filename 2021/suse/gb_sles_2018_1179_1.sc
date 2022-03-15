if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2018.1179.1" );
	script_cve_id( "CVE-2015-7554", "CVE-2016-10095", "CVE-2016-10268", "CVE-2016-3945", "CVE-2016-5318", "CVE-2016-5652", "CVE-2016-9453", "CVE-2016-9536", "CVE-2017-11335", "CVE-2017-17973", "CVE-2017-9935" );
	script_tag( name: "creation_date", value: "2021-06-09 14:57:45 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-30 16:27:00 +0000 (Tue, 30 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2018:1179-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2018:1179-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2018/suse-su-20181179-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'tiff' package(s) announced via the SUSE-SU-2018:1179-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update for tiff fixes the following issues:
- CVE-2016-9453: The t2p_readwrite_pdf_image_tile function allowed remote
 attackers to cause a denial of service (out-of-bounds write and crash)
 or possibly execute arbitrary code via a JPEG file with a
 TIFFTAG_JPEGTABLES of length one (bsc#1011107).
- CVE-2016-5652: An exploitable heap-based buffer overflow existed in the
 handling of TIFF images in the TIFF2PDF tool. A crafted TIFF document
 can lead to a heap-based buffer overflow resulting in remote code
 execution. Vulnerability can be triggered via a saved TIFF file
 delivered by other means (bsc#1007280).
- CVE-2017-11335: There is a heap based buffer overflow in
 tools/tiff2pdf.c via a PlanarConfig=Contig image, which caused a more
 than one hundred bytes out-of-bounds write (related to the ZIPDecode
 function in tif_zip.c). A crafted input may lead to a remote denial of
 service attack or an arbitrary code execution attack (bsc#1048937).
- CVE-2016-9536: tools/tiff2pdf.c had an out-of-bounds write
 vulnerabilities in heap allocated buffers in t2p_process_jpeg_strip().
 Reported as MSVR 35098, aka 't2p_process_jpeg_strip
 heap-buffer-overflow.' (bsc#1011845)
- CVE-2017-9935: In LibTIFF, there was a heap-based buffer overflow in the
 t2p_write_pdf function in tools/tiff2pdf.c. This heap overflow could
 lead to different damages. For example, a crafted TIFF document can lead
 to an out-of-bounds read in TIFFCleanup, an invalid free in TIFFClose or
 t2p_free, memory corruption in t2p_readwrite_pdf_image, or a double free
 in t2p_free. Given these possibilities, it probably could cause
 arbitrary code execution (bsc#1046077).
- CVE-2017-17973: There is a heap-based use-after-free in the
 t2p_writeproc function in tiff2pdf.c. (bsc#1074318)
- CVE-2015-7554: The _TIFFVGetField function in tif_dir.c allowed
 attackers to cause a denial of service (invalid memory write and crash)
 or possibly have unspecified other impact via crafted field data in an
 extension tag in a TIFF image (bsc#960341).
- CVE-2016-5318: Stack-based buffer overflow in the _TIFFVGetField
 function allowed remote attackers to crash the application via a crafted
 tiff (bsc#983436).
- CVE-2016-10095: Stack-based buffer overflow in the _TIFFVGetField
 function in tif_dir.c allowed remote attackers to cause a denial of
 service (crash) via a crafted TIFF file (bsc#1017690,).
- CVE-2016-10268: tools/tiffcp.c allowed remote attackers to cause a
 denial of service (integer underflow and heap-based buffer under-read)
 or possibly have unspecified other impact via a crafted TIFF image,
 related to 'READ of size 78490' and libtiff/tif_unix.c:115:23
 (bsc#1031255)
- An overlapping of memcpy parameters was fixed which could lead to
 content corruption (bsc#1017691).
- Fixed an invalid memory read which could lead to a crash (bsc#1017692).
- Fixed a NULL pointer dereference in TIFFReadRawData (tiffinfo.c) that
 could crash the decoder (bsc#1017688)." );
	script_tag( name: "affected", value: "'tiff' package(s) on SUSE Linux Enterprise Debuginfo 11-SP4, SUSE Linux Enterprise Server 11-SP4, SUSE Linux Enterprise Software Development Kit 11-SP4." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtiff3", rpm: "libtiff3~3.8.2~141.169.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff3-32bit", rpm: "libtiff3-32bit~3.8.2~141.169.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff3-x86", rpm: "libtiff3-x86~3.8.2~141.169.3.1", rls: "SLES11.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff", rpm: "tiff~3.8.2~141.169.3.1", rls: "SLES11.0SP4" ) )){
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

