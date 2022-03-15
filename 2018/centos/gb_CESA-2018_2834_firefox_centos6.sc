if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882946" );
	script_version( "2021-05-25T06:00:12+0200" );
	script_tag( name: "last_modification", value: "2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)" );
	script_tag( name: "creation_date", value: "2018-10-03 17:02:08 +0530 (Wed, 03 Oct 2018)" );
	script_cve_id( "CVE-2018-12383", "CVE-2018-12385" );
	script_tag( name: "cvss_base", value: "4.4" );
	script_tag( name: "cvss_base_vector", value: "AV:L/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 19:03:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "CentOS Update for firefox CESA-2018:2834 centos6" );
	script_tag( name: "summary", value: "Check the version of firefox" );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present
  on the target host." );
	script_tag( name: "insight", value: "Mozilla Firefox is an open-source web browser,
  designed for standards compliance, performance, and portability.

This update upgrades Firefox to version 60.2.1 ESR.

Security Fix(es):

  * Mozilla: Crash in TransportSecurityInfo due to cached data
(CVE-2018-12385)

  * Mozilla: Setting a master password post-Firefox 58 does not delete
unencrypted previously stored passwords (CVE-2018-12383)

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Philipp and Jurgen Gaeremyn as the original
reporters." );
	script_tag( name: "affected", value: "firefox on CentOS 6" );
	script_tag( name: "solution", value: "Please install the updated packages." );
	script_xref( name: "CESA", value: "2018:2834" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-September/023026.html" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
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
	if(( res = isrpmvuln( pkg: "firefox", rpm: "firefox~60.2.1~1.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

