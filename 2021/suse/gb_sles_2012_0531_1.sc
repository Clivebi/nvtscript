if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2012.0531.1" );
	script_cve_id( "CVE-2009-3743", "CVE-2010-4054" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:28 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-10-10 19:47:00 +0000 (Wed, 10 Oct 2018)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2012:0531-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES10\\.0SP4)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2012:0531-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2012/suse-su-20120531-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ghostscript' package(s) announced via the SUSE-SU-2012:0531-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of ghostscript fixes two security issues:

 * CVE-2009-3743: Off-by-one error in the TrueType bytecode interpreter in Ghostscript in SUSE Linux Enterprise 10 and 11 products allows remote attackers to cause a denial of service (heap memory corruption) via a malformed TrueType font in a document.
 * CVE-2010-4054: The gs_type2_interpret function in Ghostscript allows remote attackers to cause a denial of service (incorrect pointer dereference and application crash) via crafted font data in a compressed data stream." );
	script_tag( name: "affected", value: "'ghostscript' package(s) on SLE SDK 10 SP4, SUSE Linux Enterprise Desktop 10 SP4, SUSE Linux Enterprise Server 10 SP4." );
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
if(release == "SLES10.0SP4"){
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-fonts-other", rpm: "ghostscript-fonts-other~8.15.4~16.26.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-fonts-rus", rpm: "ghostscript-fonts-rus~8.15.4~16.26.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-fonts-std", rpm: "ghostscript-fonts-std~8.15.4~16.26.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-library", rpm: "ghostscript-library~8.15.4~16.26.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-omni", rpm: "ghostscript-omni~8.15.4~16.26.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "ghostscript-x11", rpm: "ghostscript-x11~8.15.4~16.26.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimpprint", rpm: "libgimpprint~4.2.7~62.26.1", rls: "SLES10.0SP4" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "libgimpprint-devel", rpm: "libgimpprint-devel~4.2.7~62.26.1", rls: "SLES10.0SP4" ) )){
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
