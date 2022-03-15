if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883132" );
	script_version( "2021-08-27T14:01:18+0000" );
	script_cve_id( "CVE-2019-11757", "CVE-2019-11758", "CVE-2019-11759", "CVE-2019-11760", "CVE-2019-11761", "CVE-2019-11762", "CVE-2019-11763", "CVE-2019-11764", "CVE-2019-15903" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-27 14:01:18 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-03-14 19:15:00 +0000 (Sat, 14 Mar 2020)" );
	script_tag( name: "creation_date", value: "2019-11-14 03:01:11 +0000 (Thu, 14 Nov 2019)" );
	script_name( "CentOS Update for thunderbird CESA-2019:3756 centos6 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2019:3756" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-November/023514.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2019:3756 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 68.2.0.

Security Fix(es):

  * Mozilla: Memory safety bugs fixed in Firefox 70 and Firefox ESR 68.2
(CVE-2019-11764)

  * Mozilla: Use-after-free when creating index updates in IndexedDB
(CVE-2019-11757)

  * Mozilla: Potentially exploitable crash due to 360 Total Security
(CVE-2019-11758)

  * Mozilla: Stack buffer overflow in HKDF output (CVE-2019-11759)

  * Mozilla: Stack buffer overflow in WebRTC networking (CVE-2019-11760)

  * Mozilla: Unintended access to a privileged JSONView object
(CVE-2019-11761)

  * Mozilla: document.domain-based origin isolation has same-origin-property
violation (CVE-2019-11762)

  * Mozilla: Incorrect HTML parsing results in XSS bypass technique
(CVE-2019-11763)

  * expat: heap-based buffer over-read via crafted XML input (CVE-2019-15903)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'thunderbird' package(s) on CentOS 6." );
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
	if(!isnull( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~68.2.0~2.el6.centos", rls: "CentOS6" ) )){
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

