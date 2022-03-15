if(description){
	script_xref( name: "URL", value: "https://www.redhat.com/archives/rhsa-announce/2012-October/msg00033.html" );
	script_oid( "1.3.6.1.4.1.25623.1.0.870855" );
	script_version( "2020-08-17T08:01:28+0000" );
	script_tag( name: "last_modification", value: "2020-08-17 08:01:28 +0000 (Mon, 17 Aug 2020)" );
	script_tag( name: "creation_date", value: "2012-11-02 10:59:36 +0530 (Fri, 02 Nov 2012)" );
	script_cve_id( "CVE-2012-4194", "CVE-2012-4195", "CVE-2012-4196" );
	script_tag( name: "cvss_base", value: "6.4" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:N" );
	script_xref( name: "RHSA", value: "2012:1413-01" );
	script_name( "RedHat Update for thunderbird RHSA-2012:1413-01" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the referenced advisory." );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2012 Greenbone Networks GmbH" );
	script_family( "Red Hat Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/rhel", "ssh/login/rpms",  "ssh/login/release=RHENT_6" );
	script_tag( name: "affected", value: "thunderbird on Red Hat Enterprise Linux Desktop (v. 6),
  Red Hat Enterprise Linux Workstation (v. 6)" );
	script_tag( name: "solution", value: "Please Install the Updated Packages." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

  Multiple flaws were found in the location object implementation in
  Thunderbird. Malicious content could be used to perform cross-site
  scripting attacks, bypass the same-origin policy, or cause Thunderbird to
  execute arbitrary code. (CVE-2012-4194, CVE-2012-4195, CVE-2012-4196)

  Red Hat would like to thank the Mozilla project for reporting these issues.
  Upstream acknowledges Mariusz Mlynski, moz_bug_r_a4, and Antoine
  Delignat-Lavaud as the original reporters of these issues.

  Note: None of the issues in this advisory can be exploited by a
  specially-crafted HTML mail message as JavaScript is disabled by default
  for mail messages. They could be exploited another way in Thunderbird, for
  example, when viewing the full remote content of an RSS feed.

  All Thunderbird users should upgrade to this updated package, which
  contains Thunderbird version 10.0.10 ESR, which corrects these issues.
  After installing the update, Thunderbird must be restarted for the changes
  to take effect." );
	script_tag( name: "qod_type", value: "package" );
	script_tag( name: "solution_type", value: "VendorFix" );
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
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~10.0.10~1.el6_3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(( res = isrpmvuln( pkg: "thunderbird-debuginfo", rpm: "thunderbird-debuginfo~10.0.10~1.el6_3", rls: "RHENT_6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

