if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883183" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2020-6796", "CVE-2020-6798", "CVE-2020-6800" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-12 00:15:00 +0000 (Thu, 12 Mar 2020)" );
	script_tag( name: "creation_date", value: "2020-02-19 04:01:52 +0000 (Wed, 19 Feb 2020)" );
	script_name( "CentOS: Security Advisory for firefox (CESA-2020:0520)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2020:0520" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-February/035641.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'firefox'
  package(s) announced via the CESA-2020:0520 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open-source web browser, designed for standards
compliance, performance, and portability.

This update upgrades Firefox to version 68.5.0 ESR.

Security Fix(es):

  * Mozilla: Missing bounds check on shared memory read in the parent process
(CVE-2020-6796)

  * Mozilla: Memory safety bugs fixed in Firefox 73 and Firefox ESR 68.5
(CVE-2020-6800)

  * Mozilla: Incorrect parsing of template tag could result in JavaScript
injection (CVE-2020-6798)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'firefox' package(s) on CentOS 7." );
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
if(release == "CentOS7"){
	if(!isnull( res = isrpmvuln( pkg: "firefox", rpm: "firefox~68.5.0~2.el7.centos", rls: "CentOS7" ) )){
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
