if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2014.0898.1" );
	script_cve_id( "CVE-2013-2002", "CVE-2013-2005" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:20 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-04-21 01:59:00 +0000 (Fri, 21 Apr 2017)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2014:0898-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP1)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2014:0898-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2014/suse-su-20140898-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'xorg-x11-libXt' package(s) announced via the SUSE-SU-2014:0898-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This is a SUSE Linux Enterprise Server 11 SP1 LTSS roll up update of xorg-x11-libXt, fixing security issues.

These issues require connection to a malicious X server to trigger the bugs in client libraries.

 * CVE-2013-2002: Buffer overflow in X.org libXt allowed X servers to
 cause a denial of service (crash) and possibly execute arbitrary
 code via crafted length or index values to the
 _XtResourceConfigurationEH function.
 * CVE-2013-2005: X.org libXt did not check the return value of the
 XGetWindowProperty function, which allowed X servers to trigger use
 of an uninitialized pointer and memory corruption via vectors related to the (1) ReqCleanup, (2) HandleSelectionEvents, (3) ReqTimedOut,
(4) HandleNormal, and (5) HandleSelectionReplies functions.

Security Issues references:

 * CVE-2013-2002
 * CVE-2013-2005" );
	script_tag( name: "affected", value: "'xorg-x11-libXt' package(s) on SUSE Linux Enterprise Server 11 SP1." );
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
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libXt-32bit", rpm: "xorg-x11-libXt-32bit~7.4~1.19.8", rls: "SLES11.0SP1" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-libXt", rpm: "xorg-x11-libXt~7.4~1.19.8", rls: "SLES11.0SP1" ) )){
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
