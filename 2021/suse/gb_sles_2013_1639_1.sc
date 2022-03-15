if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.1639.1" );
	script_cve_id( "CVE-2012-1173", "CVE-2012-2088", "CVE-2012-2113", "CVE-2012-3401", "CVE-2012-4447", "CVE-2012-4564", "CVE-2012-5581", "CVE-2013-1960", "CVE-2013-1961", "CVE-2013-4231", "CVE-2013-4232", "CVE-2013-4243", "CVE-2013-4244" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:23 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-08 03:03:00 +0000 (Thu, 08 Dec 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:1639-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:1639-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20131639-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'libtiff' package(s) announced via the SUSE-SU-2013:1639-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This tiff LTSS roll up update fixes several security issues.

 * CVE-2013-4232 CVE-2013-4231: buffer overflows/use after free problem
 * CVE-2013-4243: libtiff (gif2tiff): heap-based buffer overflow in readgifimage()
 * CVE-2013-4244: libtiff (gif2tiff): OOB Write in LZW decompressor
 * CVE-2013-1961: Stack-based buffer overflow with malformed image-length and resolution
 * CVE-2013-1960: Heap-based buffer overflow in t2_process_jpeg_strip()
 * CVE-2012-4447: Heap-buffer overflow when processing a TIFF image with PixarLog Compression
 * CVE-2012-4564: Added a ppm2tiff missing return value check
 * CVE-2012-5581: Fixed Stack based buffer overflow when handling DOTRANGE tags
 * CVE-2012-3401: Fixed Heap-based buffer overflow due to improper initialization of T2P context struct pointer
 * CVE-2012-2113: integer overflow leading to heap-based buffer overflow when parsing crafted tiff files
 * Another heap-based memory corruption in the tiffp2s commandline tool has been fixed [bnc#788741]
 * CVE-2012-2088: A type conversion flaw in libtiff has been fixed.
 * CVE-2012-1173: A heap based buffer overflow in TIFFReadRGBAImageOriented was fixed.

Security Issue references:

 * CVE-2012-1173
>
 * CVE-2012-2088
>
 * CVE-2012-2113
>
 * CVE-2012-3401
>
 * CVE-2012-4447
>
 * CVE-2012-4564
>
 * CVE-2012-5581
>
 * CVE-2013-1960
>
 * CVE-2013-1961
>
 * CVE-2013-4231
>
 * CVE-2013-4232
>
 * CVE-2013-4243
>
 * CVE-2013-4244
>" );
	script_tag( name: "affected", value: "'libtiff' package(s) on SUSE Linux Enterprise Server 10 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "libtiff", rpm: "libtiff~3.8.2~5.36.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff-32bit", rpm: "libtiff-32bit~3.8.2~5.36.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff-devel", rpm: "libtiff-devel~3.8.2~5.36.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libtiff-devel-32bit", rpm: "libtiff-devel-32bit~3.8.2~5.36.1", rls: "SLES10.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "tiff", rpm: "tiff~3.8.2~5.36.1", rls: "SLES10.0SP3" ) )){
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

