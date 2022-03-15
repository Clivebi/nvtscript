if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883110" );
	script_version( "2021-08-27T13:01:16+0000" );
	script_cve_id( "CVE-2019-11739", "CVE-2019-11740", "CVE-2019-11742", "CVE-2019-11743", "CVE-2019-11744", "CVE-2019-11746", "CVE-2019-11752" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-08-27 13:01:16 +0000 (Fri, 27 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-10-04 18:15:00 +0000 (Fri, 04 Oct 2019)" );
	script_tag( name: "creation_date", value: "2019-09-20 02:00:39 +0000 (Fri, 20 Sep 2019)" );
	script_name( "CentOS Update for thunderbird CESA-2019:2773 centos7 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "CESA", value: "2019:2773" );
	script_xref( name: "URL", value: "http://lists.centos.org/pipermail/centos-announce/2019-September/023410.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2019:2773 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 60.9.0.

Security Fix(es):

  * Mozilla: Covert Content Attack on S/MIME encryption using a crafted
multipart/alternative message (CVE-2019-11739)

  * Mozilla: Memory safety bugs fixed in Firefox 69, Firefox ESR 68.1, and
Firefox ESR 60.9 (CVE-2019-11740)

  * Mozilla: Same-origin policy violation with SVG filters and canvas to
steal cross-origin images (CVE-2019-11742)

  * Mozilla: XSS by breaking out of title and textarea elements using
innerHTML (CVE-2019-11744)

  * Mozilla: Use-after-free while manipulating video (CVE-2019-11746)

  * Mozilla: Use-after-free while extracting a key value in IndexedDB
(CVE-2019-11752)

  * Mozilla: Cross-origin access to unload event attributes (CVE-2019-11743)

For more details about the security issue(s), including the impact, a CVSS
score, acknowledgments, and other related information, refer to the CVE
page(s) listed in the References section." );
	script_tag( name: "affected", value: "'thunderbird' package(s) on CentOS 7." );
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
	if(!isnull( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~60.9.0~1.el7.centos", rls: "CentOS7" ) )){
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

