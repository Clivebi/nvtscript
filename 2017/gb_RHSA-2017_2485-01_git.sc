if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.871887" );
	script_version( "2021-09-10T09:01:40+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 09:01:40 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-08-17 07:50:52 +0200 (Thu, 17 Aug 2017)" );
	script_cve_id( "CVE-2017-1000117" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-03 00:03:00 +0000 (Thu, 03 Oct 2019)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "RedHat Update for git RHSA-2017:2485-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'git'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "insight", value: "Git is a distributed revision control system
  with a decentralized architecture. As opposed to centralized version control
  systems with a client-server model, Git ensures that each working copy of a Git
  repository is an exact copy with complete revision history. This not only allows
  the user to work on and contribute to projects without the need to have
  permission to push the changes to their official repositories, but also makes it
  possible for the user to work with no network connection. Security Fix(es): * A
  shell command injection flaw related to the handling of 'ssh' URLs has been
  discovered in Git. An attacker could use this flaw to execute shell commands
  with the privileges of the user running the Git client, for example, when
  performing a 'clone' action on a malicious repository or a legitimate repository
  containing a malicious commit. (CVE-2017-1000117)" );
	script_tag( name: "affected", value: "git on Red Hat Enterprise Linux Server (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_xref( name: "RHSA", value: "2017:2485-01" );
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2017-August/msg00067.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "git", rpm: "git~1.7.1~9.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "git-debuginfo", rpm: "git-debuginfo~1.7.1~9.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "perl-Git", rpm: "perl-Git~1.7.1~9.el6_9", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

