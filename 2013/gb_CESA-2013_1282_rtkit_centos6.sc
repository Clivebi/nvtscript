if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.881798" );
	script_version( "$Revision: 14222 $" );
	script_tag( name: "last_modification", value: "$Date: 2019-03-15 13:50:48 +0100 (Fri, 15 Mar 2019) $" );
	script_tag( name: "creation_date", value: "2013-10-03 10:18:34 +0530 (Thu, 03 Oct 2013)" );
	script_cve_id( "CVE-2013-4326" );
	script_tag( name: "cvss_base", value: "4.6" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:P/I:P/A:P" );
	script_name( "CentOS Update for rtkit CESA-2013:1282 centos6" );
	script_tag( name: "affected", value: "rtkit on CentOS 6" );
	script_tag( name: "insight", value: "RealtimeKit is a D-Bus system service that changes the scheduling policy of
user processes/threads to SCHED_RR (that is, realtime scheduling mode) on
request. It is intended to be used as a secure mechanism to allow real-time
scheduling to be used by normal user processes.

It was found that RealtimeKit communicated with PolicyKit for authorization
using a D-Bus API that is vulnerable to a race condition. This could have
led to intended PolicyKit authorizations being bypassed. This update
modifies RealtimeKit to communicate with PolicyKit via a different API that
is not vulnerable to the race condition. (CVE-2013-4326)

All rtkit users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue." );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "CESA", value: "2013:1282" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2013-September/019955.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'rtkit'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (c) 2013 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "rtkit", rpm: "rtkit~0.5~2.el6_4", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

