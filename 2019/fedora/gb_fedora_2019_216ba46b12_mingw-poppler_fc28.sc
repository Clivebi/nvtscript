if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875511" );
	script_version( "2021-09-02T10:01:39+0000" );
	script_cve_id( "CVE-2019-7310", "CVE-2018-20662", "CVE-2017-18267", "CVE-2018-13988", "CVE-2018-16646", "CVE-2018-19058", "CVE-2018-19059", "CVE-2018-19060", "CVE-2018-19149" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 10:01:39 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-11-09 02:15:00 +0000 (Mon, 09 Nov 2020)" );
	script_tag( name: "creation_date", value: "2019-03-16 04:13:02 +0100 (Sat, 16 Mar 2019)" );
	script_name( "Fedora Update for mingw-poppler FEDORA-2019-216ba46b12" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-216ba46b12" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/BNP6C3RSDEVJ54KVSGYBPCUC7Y63YF66" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'mingw-poppler'
  package(s) announced via the FEDORA-2019-216ba46b12 advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is present on the target host." );
	script_tag( name: "insight", value: "MinGW Windows Poppler library." );
	script_tag( name: "affected", value: "mingw-poppler on Fedora 28." );
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
	if(( res = isrpmvuln( pkg: "mingw-poppler", rpm: "mingw-poppler~0.62.0~3.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

