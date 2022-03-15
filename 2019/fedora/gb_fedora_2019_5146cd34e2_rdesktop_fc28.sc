if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875456" );
	script_version( "2021-08-31T13:01:28+0000" );
	script_cve_id( "CVE-2018-8794", "CVE-2018-8795", "CVE-2018-8797", "CVE-2018-20175", "CVE-2018-20176", "CVE-2018-8791", "CVE-2018-8792", "CVE-2018-8793", "CVE-2018-8796", "CVE-2018-8798", "CVE-2018-8799", "CVE-2018-8800", "CVE-2018-20174", "CVE-2018-20177", "CVE-2018-20178", "CVE-2018-20179", "CVE-2018-20180", "CVE-2018-20181", "CVE-2018-20182" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 13:01:28 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-09-29 01:39:00 +0000 (Tue, 29 Sep 2020)" );
	script_tag( name: "creation_date", value: "2019-02-14 04:08:04 +0100 (Thu, 14 Feb 2019)" );
	script_name( "Fedora Update for rdesktop FEDORA-2019-5146cd34e2" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-5146cd34e2" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/XPNEOV2ZX56MI4RNCZJCFJWNP6HTTFYB" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'rdesktop' package(s) announced via the FEDORA-2019-5146cd34e2 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "affected", value: "rdesktop on Fedora 28." );
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
	if(( res = isrpmvuln( pkg: "rdesktop", rpm: "rdesktop~1.8.4~2.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

