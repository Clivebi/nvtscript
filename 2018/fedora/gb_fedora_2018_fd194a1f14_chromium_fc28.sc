if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875299" );
	script_version( "2021-06-14T02:00:24+0000" );
	script_cve_id( "CVE-2018-17478", "CVE-2018-17479", "CVE-2018-16435", "CVE-2018-17462", "CVE-2018-17463", "CVE-2018-17464", "CVE-2018-17465", "CVE-2018-17466", "CVE-2018-17467", "CVE-2018-17468", "CVE-2018-17469", "CVE-2018-17470", "CVE-2018-17471", "CVE-2018-17473", "CVE-2018-17474", "CVE-2018-17475", "CVE-2018-17476", "CVE-2018-5179", "CVE-2018-17477", "CVE-2018-17472" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-06-14 02:00:24 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-06-28 16:25:00 +0000 (Fri, 28 Jun 2019)" );
	script_tag( name: "creation_date", value: "2018-12-04 08:19:58 +0100 (Tue, 04 Dec 2018)" );
	script_name( "Fedora Update for chromium FEDORA-2018-fd194a1f14" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2018 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2018-fd194a1f14" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/EGYVJ7TOEEFWMXPEHXQHYSD6LDOEY736" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'chromium'
  package(s) announced via the FEDORA-2018-fd194a1f14 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "affected", value: "chromium on Fedora 28." );
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
if(release == "FC28"){
	if(( res = isrpmvuln( pkg: "chromium", rpm: "chromium~70.0.3538.110~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

