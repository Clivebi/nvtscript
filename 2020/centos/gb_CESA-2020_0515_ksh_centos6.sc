if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883185" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2019-14868" );
	script_tag( name: "cvss_base", value: "7.2" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:L/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-09 13:46:00 +0000 (Fri, 09 Oct 2020)" );
	script_tag( name: "creation_date", value: "2020-02-19 04:01:56 +0000 (Wed, 19 Feb 2020)" );
	script_name( "CentOS: Security Advisory for ksh (CESA-2020:0515)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:0515" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-February/035640.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'ksh'
  package(s) announced via the CESA-2020:0515 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "KornShell (ksh) is a Unix shell developed by AT&T Bell Laboratories, which
is backward-compatible with the Bourne shell (sh) and includes many
features of the C shell. The most recent version is KSH-93. KornShell
complies with the POSIX.2 standard (IEEE Std 1003.2-1992).

Security Fix(es):

  * ksh: certain environment variables interpreted as arithmetic expressions
on startup, leading to code injection (CVE-2019-14868)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'ksh' package(s) on CentOS 6." );
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
if(release == "CentOS6"){
	if(!isnull( res = isrpmvuln( pkg: "ksh", rpm: "ksh~20120801~38.el6_10", rls: "CentOS6" ) )){
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

