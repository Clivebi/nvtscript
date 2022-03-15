if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.882970" );
	script_version( "2021-05-25T06:00:12+0200" );
	script_cve_id( "CVE-2017-16541", "CVE-2018-12376", "CVE-2018-12377", "CVE-2018-12378", "CVE-2018-12379", "CVE-2018-12383", "CVE-2018-12385" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-05-25 06:00:12 +0200 (Tue, 25 May 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-12-06 15:50:00 +0000 (Thu, 06 Dec 2018)" );
	script_tag( name: "creation_date", value: "2018-11-09 06:05:06 +0100 (Fri, 09 Nov 2018)" );
	script_name( "CentOS Update for thunderbird CESA-2018:3403 centos6" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2018:3403" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2018-November/023078.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2018:3403 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 60.2.1.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 62 and Firefox ESR 60.2
(CVE-2018-12376)

  * Mozilla: Use-after-free in driver timers (CVE-2018-12377)

  * Mozilla: Use-after-free in IndexedDB (CVE-2018-12378)

  * Mozilla: Proxy bypass using automount and autofs (CVE-2017-16541)

  * Mozilla: Out-of-bounds write with malicious MAR file (CVE-2018-12379)

  * Mozilla: Crash in TransportSecurityInfo due to cached data
(CVE-2018-12385)

  * Mozilla: Setting a master password post-Firefox 58 does not delete
unencrypted previously stored passwords (CVE-2018-12383)

Note: All of the above issues cannot be exploited in Thunderbird by a
specially crafted HTML mail, as JavaScript is disabled for mail messages
and cannot be enabled. They could be exploited another way in Thunderbird,
for example, when viewing the remote content of an RSS feed.

For more details about the security issue(s), including the impact, a CVSS
score, and other related information, refer to the CVE page(s) listed in
the References section.

Red Hat would like to thank the Mozilla project for reporting these issues.
Upstream acknowledges Alex Gaynor, Boris Zbarsky, Christoph Diehl,
Christian Holler, Jason Kratzer, Jed Davis, Tyson Smith, Bogdan Tara, Karl
Tomlinson, Mats Palmgren, Nika Layzell, Ted Campbell, Nils, Zhanjia Song,
Holger Fuhrmannek, Philipp, and Jurgen Gaeremyn as the original reporters." );
	script_tag( name: "affected", value: "thunderbird on CentOS 6." );
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
if(release == "CentOS6"){
	if(( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~60.2.1~5.el6.centos", rls: "CentOS6" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

