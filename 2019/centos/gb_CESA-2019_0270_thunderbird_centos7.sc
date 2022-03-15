if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883006" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_cve_id( "CVE-2016-5824", "CVE-2018-18500", "CVE-2018-18501", "CVE-2018-18505" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-02 07:29:00 +0000 (Tue, 02 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-02-10 04:04:06 +0100 (Sun, 10 Feb 2019)" );
	script_name( "CentOS Update for thunderbird CESA-2019:0270 centos7" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:0270" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-February/023193.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2019:0270 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 60.5.0.

Security Fix(es):

  * Mozilla: Use-after-free parsing HTML5 stream (CVE-2018-18500)

  * Mozilla: Memory safety bugs fixed in Firefox 65 and Firefox ESR 60.5
(CVE-2018-18501)

  * Mozilla: Privilege escalation through IPC channel messages
(CVE-2018-18505)

  * libical: Multiple use-after-free vulnerabilities (CVE-2016-5824)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Yaniv Frank (SophosLabs), Alex Gaynor, Christoph
Diehl, Steven Crane, Jason Kratzer, Gary Kwong, Christian Holler, and Jed
Davis as the original reporters." );
	script_tag( name: "affected", value: "thunderbird on CentOS 7." );
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
if(release == "CentOS7"){
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~60.5.0~1.el7.centos", rls: "CentOS7" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

