if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871732" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-12-22 05:44:49 +0100 (Thu, 22 Dec 2016)" );
	script_cve_id( "CVE-2016-9445", "CVE-2016-9447" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for gstreamer-plugins-bad-free RHSA-2016:2974-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'gstreamer-plugins-bad-free'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "GStreamer is a streaming media framework
based on graphs of filters which operate on media data. The
gstreamer-plugins-bad-free package contains a collection of plug-ins for GStreamer.

Security Fix(es):

  * An integer overflow flaw, leading to a heap-based buffer overflow, was
found in GStreamer's VMware VMnc video file format decoding plug-in. A
remote attacker could use this flaw to cause an application using GStreamer
to crash or, potentially, execute arbitrary code with the privileges of the
user running the application. (CVE-2016-9445)

  * A memory corruption flaw was found in GStreamer's Nintendo NSF music file
format decoding plug-in. A remote attacker could use this flaw to cause an
application using GStreamer to crash or, potentially, execute arbitrary
code with the privileges of the user running the application.
(CVE-2016-9447)

Note: This updates removes the vulnerable Nintendo NSF plug-in." );
	script_tag( name: "affected", value: "gstreamer-plugins-bad-free on
  Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:2974-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-December/msg00026.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2016 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_6"){
	if(( res = isrpmvuln( pkg: "gstreamer-plugins-bad-free", rpm: "gstreamer-plugins-bad-free~0.10.19~5.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "gstreamer-plugins-bad-free-debuginfo", rpm: "gstreamer-plugins-bad-free-debuginfo~0.10.19~5.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

