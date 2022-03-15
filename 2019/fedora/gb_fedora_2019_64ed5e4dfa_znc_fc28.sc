if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875572" );
	script_version( "2021-09-02T12:01:30+0000" );
	script_cve_id( "CVE-2019-9917" );
	script_tag( name: "cvss_base", value: "4.0" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:S/C:N/I:N/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 12:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-15 03:29:00 +0000 (Sat, 15 Jun 2019)" );
	script_tag( name: "creation_date", value: "2019-04-24 02:10:03 +0000 (Wed, 24 Apr 2019)" );
	script_name( "Fedora Update for znc FEDORA-2019-64ed5e4dfa" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-64ed5e4dfa" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/WRHCMHI44AW5CJ22WV676BKFUWWCLA7T" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'znc' package(s) announced via the FEDORA-2019-64ed5e4dfa advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "insight", value: "ZNC is an IRC bouncer with many advanced
  features like detaching, multiple users, per channel playback buffer, SSL,
  IPv6, transparent DCC bouncing, Perl and C++ module support to name a few." );
	script_tag( name: "affected", value: "'znc' package(s) on Fedora 28." );
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
if(release == "FC28"){
	if(!isnull( res = isrpmvuln( pkg: "znc", rpm: "znc~1.7.3~1.fc28", rls: "FC28" ) )){
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

