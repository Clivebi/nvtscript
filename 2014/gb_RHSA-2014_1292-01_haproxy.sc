if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871249" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2014-09-25 05:58:12 +0200 (Thu, 25 Sep 2014)" );
	script_cve_id( "CVE-2014-6269" );
	script_tag( name: "cvss_base", value: "5.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:N/I:N/A:P" );
	script_name( "RedHat Update for haproxy RHSA-2014:1292-01" );
	script_tag( name: "insight", value: "HAProxy provides high availability, load balancing, and proxying for TCP
and HTTP-based applications.

A buffer overflow flaw was discovered in the way HAProxy handled, under
very specific conditions, data uploaded from a client. A remote attacker
could possibly use this flaw to crash HAProxy. (CVE-2014-6269)

All haproxy users are advised to upgrade to this updated package, which
contains a backported patch to correct this issue." );
	script_tag( name: "affected", value: "haproxy on Red Hat Enterprise Linux Server (v. 7)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_xref( name: "RHSA", value: "2014:1292-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2014-September/msg00047.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'haproxy'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2014 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_7" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "RHENT_7"){
	if(( res = isrpmvuln( pkg: "haproxy", rpm: "haproxy~1.5.2~3.el7_0", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "haproxy-debuginfo", rpm: "haproxy-debuginfo~1.5.2~3.el7_0", rls: "RHENT_7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

