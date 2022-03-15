if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2015.0674.1" );
	script_cve_id( "CVE-2015-1802", "CVE-2015-1803", "CVE-2015-1804" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:13 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "8.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:S/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2016-12-22 02:59:00 +0000 (Thu, 22 Dec 2016)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2015:0674-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP3)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2015:0674-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2015/suse-su-20150674-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-libs' package(s) announced via the SUSE-SU-2015:0674-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "LibXFont was updated to fix security problems that could be used by local attackers to gain X server privileges (root).

The following security issues have been fixed:

 *

 CVE-2015-1802: The bdf parser reads a count for the number of properties defined in a font from the font file, and allocates arrays with entries for each property based on that count. It never checked to see if that count was negative, or large enough to overflow when multiplied by the size of the structures being allocated, and could thus allocate the wrong buffer size, leading to out of bounds writes.

 *

 CVE-2015-1803: If the bdf parser failed to parse the data for the bitmap for any character, it would proceed with an invalid pointer to the bitmap data and later crash when trying to read the bitmap from that pointer.

 *

 CVE-2015-1804: The bdf parser read metrics values as 32-bit integers, but stored them into 16-bit integers. Overflows could occur in various operations leading to out-of-bounds memory access.

Security Issues:

 * CVE-2015-1802
 * CVE-2015-1803
 * CVE-2015-1804" );
	script_tag( name: "affected", value: "'xorg-x11-libs' package(s) on SUSE Linux Enterprise Desktop 11 SP3, SUSE Linux Enterprise Server 11 SP3, SUSE Linux Enterprise Software Development Kit 11 SP3." );
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
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-32bit", rpm: "xorg-x11-libs-32bit~7.4~8.26.44.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs", rpm: "xorg-x11-libs~7.4~8.26.44.1", rls: "SLES11.0SP3" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libs-x86", rpm: "xorg-x11-libs-x86~7.4~8.26.44.1", rls: "SLES11.0SP3" ) )){
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

