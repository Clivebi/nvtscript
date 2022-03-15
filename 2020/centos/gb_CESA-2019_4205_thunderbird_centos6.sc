if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883150" );
	script_version( "2021-07-06T02:00:40+0000" );
	script_cve_id( "CVE-2019-17005", "CVE-2019-17008", "CVE-2019-17010", "CVE-2019-17011", "CVE-2019-17012" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-06 02:00:40 +0000 (Tue, 06 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-01-16 19:15:00 +0000 (Thu, 16 Jan 2020)" );
	script_tag( name: "creation_date", value: "2020-01-08 11:14:53 +0000 (Wed, 08 Jan 2020)" );
	script_name( "CentOS Update for thunderbird CESA-2019:4205 centos6 " );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2019:4205" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2019-December/035580.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2019:4205 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 68.3.0.

Security Fix(es):

  * Mozilla: Use-after-free in worker destruction (CVE-2019-17008)

  * Mozilla: Memory safety bugs fixed in Firefox 71 and Firefox ESR 68.3
(CVE-2019-17012)

  * Mozilla: Buffer overflow in plain text serializer (CVE-2019-17005)

  * Mozilla: Use-after-free when performing device orientation checks
(CVE-2019-17010)

  * Mozilla: Use-after-free when retrieving a document in antitracking
(CVE-2019-17011)

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
	if(!isnull( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~68.3.0~3.el6.centos", rls: "CentOS6" ) )){
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

