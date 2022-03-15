if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871631" );
	script_version( "$Revision: 12497 $" );
	script_tag( name: "last_modification", value: "$Date: 2018-11-23 09:28:21 +0100 (Fri, 23 Nov 2018) $" );
	script_tag( name: "creation_date", value: "2016-06-22 05:28:29 +0200 (Wed, 22 Jun 2016)" );
	script_cve_id( "CVE-2016-4444", "CVE-2016-4445", "CVE-2016-4446", "CVE-2016-4989" );
	script_tag( name: "cvss_base", value: "6.9" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for setroubleshoot and setroubleshoot-plugins RHSA-2016:1267-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'setroubleshoot and setroubleshoot-plugins'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "The setroubleshoot packages provide tools to
help diagnose SELinux problems. When Access Vector Cache (AVC) messages are
returned, an alert can be generated that provides information about the problem and
helps to track its resolution.

The setroubleshoot-plugins package provides a set of analysis plugins for
use with setroubleshoot. Each plugin has the capacity to analyze SELinux
AVC data and system data to provide user friendly reports describing how to
interpret SELinux AVC denials.

Security Fix(es):

  * Shell command injection flaws were found in the way the setroubleshoot
executed external commands. A local attacker able to trigger certain
SELinux denials could use these flaws to execute arbitrary code with root
privileges. (CVE-2016-4445, CVE-2016-4989)

  * Shell command injection flaws were found in the way the setroubleshoot
allow_execmod and allow_execstack plugins executed external commands. A
local attacker able to trigger an execmod or execstack SELinux denial could
use these flaws to execute arbitrary code with root privileges.
(CVE-2016-4444, CVE-2016-4446)

The CVE-2016-4444 and CVE-2016-4446 issues were discovered by Milos Malik
(Red Hat) and the CVE-2016-4445 and CVE-2016-4989 issues were discovered by
Red Hat Product Security." );
	script_tag( name: "affected", value: "setroubleshoot and setroubleshoot-plugins
on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2016:1267-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2016-June/msg00016.html" );
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
	if(( res = isrpmvuln( pkg: "setroubleshoot", rpm: "setroubleshoot~3.0.47~12.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "setroubleshoot-debuginfo", rpm: "setroubleshoot-debuginfo~3.0.47~12.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "setroubleshoot-server", rpm: "setroubleshoot-server~3.0.47~12.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "setroubleshoot-plugins", rpm: "setroubleshoot-plugins~3.0.40~3.1.el6_8", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

