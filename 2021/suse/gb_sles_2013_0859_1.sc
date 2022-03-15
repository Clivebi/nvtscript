if(description){
	script_oid( "1.3.6.1.4.1.25623.1.1.4.2013.0859.1" );
	script_cve_id( "CVE-2013-1940" );
	script_tag( name: "creation_date", value: "2021-06-09 14:58:24 +0000 (Wed, 09 Jun 2021)" );
	script_version( "2021-08-19T02:25:52+0000" );
	script_tag( name: "last_modification", value: "2021-08-19 02:25:52 +0000 (Thu, 19 Aug 2021)" );
	script_tag( name: "cvss_base", value: "2.1" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:N/A:N" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2013-06-21 03:17:00 +0000 (Fri, 21 Jun 2013)" );
	script_name( "SUSE: Security Advisory (SUSE-SU-2013:0859-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "SuSE Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/suse_sles", "ssh/login/rpms",  "ssh/login/release=(SLES11\\.0SP2)" );
	script_xref( name: "Advisory-ID", value: "SUSE-SU-2013:0859-1" );
	script_xref( name: "URL", value: "https://www.suse.com/support/update/announcement/2013/suse-su-20130859-1/" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'Xorg' package(s) announced via the SUSE-SU-2013:0859-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "This update of xorg-x11-server fixes one security issue and two bugs.

In some cases, input events are sent to X servers not currently the VT owner, allowing a user to capture passwords. (CVE-2013-1940)

Also the following bugs have been fixed:

 * A memory leak in cursor handling could slowly run the X server out of memory. (bnc#813178)
 * A memory leak in the X GE extension has been fixed that could have also run the X server out of memory
(bnc#813683)
 * A CAPS lock issue in VNC has been fixed (bnc#787170)

Security Issue reference:

 * CVE-2013-1940
>" );
	script_tag( name: "affected", value: "'Xorg' package(s) on SUSE Linux Enterprise Desktop 11 SP2, SUSE Linux Enterprise Server 11 SP2, SUSE Linux Enterprise Software Development Kit 11 SP2." );
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
if(release == "SLES11.0SP2"){
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-Xvnc", rpm: "xorg-x11-Xvnc~7.4~27.70.72.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server", rpm: "xorg-x11-server~7.4~27.70.72.1", rls: "SLES11.0SP2" ) )){
		report += res;
	}
	if(!isnull( res = isrpmvuln( pkg: "xorg-x11-server-extra", rpm: "xorg-x11-server-extra~7.4~27.70.72.1", rls: "SLES11.0SP2" ) )){
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
