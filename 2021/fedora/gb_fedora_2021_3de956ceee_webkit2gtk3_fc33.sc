if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.879933" );
	script_version( "2021-09-20T08:01:57+0000" );
	script_cve_id( "CVE-2021-30758", "CVE-2021-21775", "CVE-2021-21779", "CVE-2021-30663", "CVE-2021-30665", "CVE-2021-30689", "CVE-2021-30720", "CVE-2021-30734", "CVE-2021-30744", "CVE-2021-30749", "CVE-2021-30795", "CVE-2021-30797", "CVE-2021-30799" );
	script_tag( name: "cvss_base", value: "9.3" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:C/I:C/A:C" );
	script_tag( name: "last_modification", value: "2021-09-20 08:01:57 +0000 (Mon, 20 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-09-16 14:10:00 +0000 (Thu, 16 Sep 2021)" );
	script_tag( name: "creation_date", value: "2021-08-13 03:13:22 +0000 (Fri, 13 Aug 2021)" );
	script_name( "Fedora: Security Advisory for webkit2gtk3 (FEDORA-2021-3de956ceee)" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2021 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC33" );
	script_xref( name: "Advisory-ID", value: "FEDORA-2021-3de956ceee" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/KYMMBQN4PRVDLMIJT2LY2BWHLYBD57P3" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'webkit2gtk3'
  package(s) announced via the FEDORA-2021-3de956ceee advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "WebKitGTK is the port of the portable web rendering engine WebKit to the
GTK platform.

This package contains WebKit2 based WebKitGTK for GTK 3." );
	script_tag( name: "affected", value: "'webkit2gtk3' package(s) on Fedora 33." );
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
if(release == "FC33"){
	if(!isnull( res = isrpmvuln( pkg: "webkit2gtk3", rpm: "webkit2gtk3~2.32.3~1.fc33", rls: "FC33" ) )){
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

