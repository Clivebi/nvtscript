if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875421" );
	script_version( "2021-09-01T10:01:36+0000" );
	script_cve_id( "CVE-2018-16884" );
	script_tag( name: "cvss_base", value: "6.7" );
	script_tag( name: "cvss_base_vector", value: "AV:A/AC:L/Au:S/C:P/I:P/A:C" );
	script_tag( name: "last_modification", value: "2021-09-01 10:01:36 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2021-06-14 18:15:00 +0000 (Mon, 14 Jun 2021)" );
	script_tag( name: "creation_date", value: "2019-01-22 04:04:40 +0100 (Tue, 22 Jan 2019)" );
	script_name( "Fedora Update for kernel-headers FEDORA-2019-20a89ca9af" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-20a89ca9af" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/IAS2Y3E3UVJ2R3GRYSJCN37FQSNZFXNR" );
	script_tag( name: "summary", value: "The remote host is missing an update for
  the 'kernel-headers' package(s) announced via the FEDORA-2019-20a89ca9af advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "affected", value: "kernel-headers on Fedora 28." );
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
	if(( res = isrpmvuln( pkg: "kernel-headers", rpm: "kernel-headers~4.19.16~200.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

