if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.875448" );
	script_version( "2021-08-31T14:01:23+0000" );
	script_cve_id( "CVE-2019-6798", "CVE-2019-6799" );
	script_tag( name: "cvss_base", value: "7.5" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:L/Au:N/C:P/I:P/A:P" );
	script_tag( name: "last_modification", value: "2021-08-31 14:01:23 +0000 (Tue, 31 Aug 2021)" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2019-01-28 15:55:00 +0000 (Mon, 28 Jan 2019)" );
	script_tag( name: "creation_date", value: "2019-02-09 04:06:13 +0100 (Sat, 09 Feb 2019)" );
	script_name( "Fedora Update for phpMyAdmin FEDORA-2019-6cfd17b03d" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2019 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC28" );
	script_xref( name: "FEDORA", value: "2019-6cfd17b03d" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/J5RYT7JLDXJ7CA6ZUFHH2FBIQTNRSI6C" );
	script_tag( name: "summary", value: "The remote host is missing an update
  for the 'phpMyAdmin' package(s) announced via the FEDORA-2019-6cfd17b03d
  advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable package version
  is present on the target host." );
	script_tag( name: "affected", value: "phpMyAdmin on Fedora 28." );
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
	if(( res = isrpmvuln( pkg: "phpMyAdmin", rpm: "phpMyAdmin~4.8.5~1.fc28", rls: "FC28" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

