if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.892524" );
	script_version( "2021-08-24T09:01:06+0000" );
	script_cve_id( "CVE-2017-15108", "CVE-2020-25650", "CVE-2020-25651", "CVE-2020-25652", "CVE-2020-25653" );
	script_tag( name: "cvss_base", value: "5.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:N/A:C" );
	script_tag( name: "last_modification", value: "2021-08-24 09:01:06 +0000 (Tue, 24 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-02-19 17:38:00 +0000 (Fri, 19 Feb 2021)" );
	script_tag( name: "creation_date", value: "2021-01-14 04:00:10 +0000 (Thu, 14 Jan 2021)" );
	script_name( "Debian LTS: Security Advisory for spice-vdagent (DLA-2524-1)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Debian Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/debian_linux", "ssh/login/packages",  "ssh/login/release=DEB9" );
	script_xref( name: "URL", value: "https://lists.debian.org/debian-lts-announce/2021/01/msg00012.html" );
	script_xref( name: "URL", value: "https://security-tracker.debian.org/tracker/DLA-2524-1" );
	script_xref( name: "URL", value: "https://bugs.debian.org/883238" );
	script_xref( name: "URL", value: "https://bugs.debian.org/973769" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'spice-vdagent'
  package(s) announced via the DLA-2524-1 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Several vulnerabilities were discovered in spice-vdagent, a spice
guest agent for enchancing SPICE integeration and experience.

CVE-2017-15108

spice-vdagent does not properly escape save directory before
passing to shell, allowing local attacker with access to the
session the agent runs in to inject arbitrary commands to be
executed.

CVE-2020-25650

A flaw was found in the way the spice-vdagentd daemon handled file
transfers from the host system to the virtual machine. Any
unprivileged local guest user with access to the UNIX domain
socket path `/run/spice-vdagentd/spice-vdagent-sock` could use
this flaw to perform a memory denial of service for spice-vdagentd
or even other processes in the VM system. The highest threat from
this vulnerability is to system availability. This flaw affects
spice-vdagent versions 0.20 and previous versions.

CVE-2020-25651

A flaw was found in the SPICE file transfer protocol. File data
from the host system can end up in full or in parts in the client
connection of an illegitimate local user in the VM system. Active
file transfers from other users could also be interrupted,
resulting in a denial of service. The highest threat from this
vulnerability is to data confidentiality as well as system
availability.

CVE-2020-25652

A flaw was found in the spice-vdagentd daemon, where it did not
properly handle client connections that can be established via the
UNIX domain socket in `/run/spice-vdagentd/spice-vdagent-sock`.
Any unprivileged local guest user could use this flaw to prevent
legitimate agents from connecting to the spice-vdagentd daemon,
resulting in a denial of service. The highest threat from this
vulnerability is to system availability.

CVE-2020-25653

A race condition vulnerability was found in the way the
spice-vdagentd daemon handled new client connections. This flaw
may allow an unprivileged local guest user to become the active
agent for spice-vdagentd, possibly resulting in a denial of
service or information leakage from the host. The highest threat
from this vulnerability is to data confidentiality as well as
system availability." );
	script_tag( name: "affected", value: "'spice-vdagent' package(s) on Debian Linux." );
	script_tag( name: "solution", value: "For Debian 9 stretch, these problems have been fixed in version
0.17.0-1+deb9u1.

We recommend that you upgrade your spice-vdagent packages." );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_tag( name: "qod_type", value: "package" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-deb.inc.sc");
res = "";
report = "";
if(!isnull( res = isdpkgvuln( pkg: "spice-vdagent", ver: "0.17.0-1+deb9u1", rls: "DEB9" ) )){
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

