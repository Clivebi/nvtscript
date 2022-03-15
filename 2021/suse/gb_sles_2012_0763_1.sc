if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0763.1" );
	script_cve_id( "CVE-2012-0247", "CVE-2012-0248", "CVE-2012-0259", "CVE-2012-0260", "CVE-2012-1185", "CVE-2012-1186", "CVE-2012-1610", "CVE-2012-1798" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:27 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-07-31 18:39:00 +0000 (Fri, 31 Jul 2020)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0763-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1|SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0763-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120763-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ImageMagick' package(s) announced via the SUSE-SU-2012:0763-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of ImageMagick fixes multiple security vulnerabilities that could be exploited by attackers via specially crafted image files:

 * CVE-2012-0259 / CVE-2012-1610: Integer overflow when processing EXIF directory entries with tags of e.g. format 5 (EXIF_FMT_URATIONAL) and a large components count.
 * CVE-2012-0247 / CVE-2012-1185: Integer overflows via
'number_bytes' and 'offset' could lead to memory corruption. CVE-2012-0248 / CVE-2012-1186: Denial of service via 'profile.c'.
 * CVE-2012-0260: Denial of service via JPEG restart markers (excessive CPU consumption).
 * CVE-2012-1798: Copying of invalid memory when reading TIFF EXIF IFD.

Security Issue references:

 * CVE-2012-0247
>
 * CVE-2012-0248
>
 * CVE-2012-1185
>
 * CVE-2012-1186
>
 * CVE-2012-0259
>
 * CVE-2012-0260
>
 * CVE-2012-1798
>
 * CVE-2012-1610
>" );
	script_tag( name: "affected", value: "'ImageMagick' package(s) on SUSE Linux Enterprise Desktop 11 SP1, SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 11 SP1, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP1, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
if(release == "SLES11.0SP1"){
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1-32bit", rpm: "libMagickCore1-32bit~6.4.3.6~7.24.1", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1", rpm: "libMagickCore1~6.4.3.6~7.24.1", rls: "SLES11.0SP1" ) )){
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
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1-32bit", rpm: "libMagickCore1-32bit~6.4.3.6~7.24.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libMagickCore1", rpm: "libMagickCore1~6.4.3.6~7.24.1", rls: "SLES11.0SP2" ) )){
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

