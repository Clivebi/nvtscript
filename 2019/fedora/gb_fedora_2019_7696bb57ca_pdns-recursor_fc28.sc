if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875457" );
	script_version( "2021-09-02T12:01:30+0000" );
	script_cve_id( "CVE-2019-3807", "CVE-2019-3806", "CVE-2018-16855", "CVE-2018-10851", "CVE-2018-14626", "CVE-2018-14644" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-02 12:01:30 +0000 (Thu, 02 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2020-10-19 17:45:00 +0000 (Mon, 19 Oct 2020)" );
	script_tag( name: "creation_date", value: "2019-02-14 04:08:52 +0100 (Thu, 14 Feb 2019)" );
	script_name( "Fedora Update for pdns-recursor FEDORA-2019-7696bb57ca" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-7696bb57ca" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/73UMB6EAQOQX32DTUYB3GHOSOEDPMURR" );
	script_tag( name: "summary", value: "The remote host is missing an update for the
  'pdns-recursor' package(s) announced via the FEDORA-2019-7696bb57ca advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version is
  present on the target host." );
	script_tag( name: "affected", value: "pdns-recursor on Fedora 28." );
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
	if(( res = isrpmvuln( pkg: "pdns-recursor", rpm: "pdns-recursor~4.1.9~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}
