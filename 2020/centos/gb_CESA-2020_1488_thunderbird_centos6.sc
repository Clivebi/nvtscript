if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883223" );
	script_version( "2021-07-05T11:01:33+0000" );
	script_cve_id( "CVE-2020-6819", "CVE-2020-6820", "CVE-2020-6821", "CVE-2020-6822", "CVE-2020-6825" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-07-05 11:01:33 +0000 (Mon, 05 Jul 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-05-01 16:07:00 +0000 (Fri, 01 May 2020)" );
	script_tag( name: "creation_date", value: "2020-04-28 03:00:53 +0000 (Tue, 28 Apr 2020)" );
	script_name( "CentOS: Security Advisory for thunderbird (CESA-2020:1488)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2020 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS6" );
	script_xref( name: "CESA", value: "2020:1488" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2020-April/035698.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2020:1488 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 68.7.0.

Security Fix(es):

  * Mozilla: Use-after-free while running the nsDocShell destructor
(CVE-2020-6819)

  * Mozilla: Use-after-free when handling a ReadableStream (CVE-2020-6820)

  * Mozilla: Uninitialized memory could be read when using the WebGL
copyTexSubImage method (CVE-2020-6821)

  * Mozilla: Memory safety bugs fixed in Firefox 75 and Firefox ESR 68.7
(CVE-2020-6825)

  * Mozilla: Out of bounds write in GMPDecodeData when processing large
images (CVE-2020-6822)

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
	if(!isnull( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~68.7.0~1.el6.centos", rls: "CentOS6" ) )){
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
