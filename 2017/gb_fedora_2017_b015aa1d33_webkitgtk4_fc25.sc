if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.872277" );
	script_version( "2021-09-10T14:25:39+0000" );
	script_tag( name: "last_modification", value: "2021-09-10 14:25:39 +0000 (Fri, 10 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-01-21 05:43:47 +0100 (Sat, 21 Jan 2017)" );
	script_cve_id( "CVE-2016-7656", "CVE-2016-7635", "CVE-2016-7654", "CVE-2016-7639", "CVE-2016-7645", "CVE-2016-7652", "CVE-2016-7641", "CVE-2016-7632", "CVE-2016-7599", "CVE-2016-7592", "CVE-2016-7589", "CVE-2016-7623", "CVE-2016-7586" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2017-07-27 01:29:00 +0000 (Thu, 27 Jul 2017)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for webkitgtk4 FEDORA-2017-b015aa1d33" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkitgtk4'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "webkitgtk4 on Fedora 25" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-b015aa1d33" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/YFXBJCFVQISXI5ANQSV54FXX56RHHQQC" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC25" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC25"){
	if(( res = isrpmvuln( pkg: "webkitgtk4", rpm: "webkitgtk4~2.14.3~1.fc25", rls: "FC25" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

