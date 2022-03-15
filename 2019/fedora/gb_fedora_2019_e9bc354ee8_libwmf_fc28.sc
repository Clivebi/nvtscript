if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875451" );
	script_version( "2021-09-01T08:01:24+0000" );
	script_cve_id( "CVE-2019-6978" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-09-01 08:01:24 +0000 (Wed, 01 Sep 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-04-05 00:29:00 +0000 (Fri, 05 Apr 2019)" );
	script_tag( name: "creation_date", value: "2019-02-10 04:06:09 +0100 (Sun, 10 Feb 2019)" );
	script_name( "Fedora Update for libwmf FEDORA-2019-e9bc354ee8" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-e9bc354ee8" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/N6H5ZFHH5O5AEGGMYAJ553JGDJZY7YXL" );
	script_tag( name: "summary", value: "The remote host is missing an update
  for the 'libwmf' package(s) announced via the FEDORA-2019-e9bc354ee8
  advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
  is present on the target host." );
	script_tag( name: "affected", value: "libwmf on Fedora 28." );
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
	if(( res = isrpmvuln( pkg: "libwmf", rpm: "libwmf~0.2.12~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

