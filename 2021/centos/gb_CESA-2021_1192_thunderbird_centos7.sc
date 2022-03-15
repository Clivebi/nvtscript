if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.883339" );
	script_version( "2021-08-17T06:00:55+0000" );
	script_cve_id( "CVE-2021-23991", "CVE-2021-23992", "CVE-2021-23993" );
	script_tag( name: "cvss_base", value: "4.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:N/I:P/A:N" );
	script_tag( name: "last_modification", value: "2021-08-17 06:00:55 +0000 (Tue, 17 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-07-08 15:47:00 +0000 (Thu, 08 Jul 2021)" );
	script_tag( name: "creation_date", value: "2021-04-17 03:00:30 +0000 (Sat, 17 Apr 2021)" );
	script_name( "CentOS: Security Advisory for thunderbird (CESA-2021:1192)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "CentOS Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/centos", "ssh/login/rpms",  "ssh/login/release=CentOS7" );
	script_xref( name: "Advisory-ID", value: "CESA-2021:1192" );
	script_xref( name: "URL", value: "https://lists.centos.org/pipermail/centos-announce/2021-April/048303.html" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'thunderbird'
  package(s) announced via the CESA-2021:1192 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "Mozilla Thunderbird is a standalone mail and newsgroup client.

This update upgrades Thunderbird to version 78.9.1.

Security Fix(es):

  * Mozilla: An attacker may use Thunderbird's OpenPGP key refresh mechanism
to poison an existing key (CVE-2021-23991)

  * Mozilla: A crafted OpenPGP key with an invalid user ID could be used to
confuse the user (CVE-2021-23992)

  * Mozilla: Inability to send encrypted OpenPGP email after importing a
crafted OpenPGP key (CVE-2021-23993)

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
	if(!isnull( res = isrpmvuln( pkg: "thunderbird", rpm: "thunderbird~78.9.1~1.el7.centos", rls: "CentOS7" ) )){
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

