if(description){
	script_oid( "1.3.6.1.4.1.25623.1.0.873950" );
	script_version( "2021-09-13T08:01:46+0000" );
	script_tag( name: "last_modification", value: "2021-09-13 08:01:46 +0000 (Mon, 13 Sep 2021)" );
	script_tag( name: "creation_date", value: "2017-12-29 08:05:03 +0100 (Fri, 29 Dec 2017)" );
	script_cve_id( "CVE-2017-17512" );
	script_tag( name: "cvss_base", value: "6.8" );
	script_tag( name: "cvss_base_vector", value: "AV:N/AC:M/Au:N/C:P/I:P/A:P" );
	script_tag( name: "severity_vector", value: "CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H" );
	script_tag( name: "severity_origin", value: "NVD" );
	script_tag( name: "severity_date", value: "2018-03-16 01:29:00 +0000 (Fri, 16 Mar 2018)" );
	script_tag( name: "qod_type", value: "package" );
	script_name( "Fedora Update for sensible-utils FEDORA-2017-2fab3f12c4" );
	script_tag( name: "summary", value: "The remote host is missing an update for the 'sensible-utils'
  package(s) announced via the referenced advisory." );
	script_tag( name: "vuldetect", value: "Checks if a vulnerable version is present on the target host." );
	script_tag( name: "affected", value: "sensible-utils on Fedora 27" );
	script_tag( name: "solution", value: "Please install the updated package(s)." );
	script_xref( name: "FEDORA", value: "2017-2fab3f12c4" );
	script_xref( name: "URL", value: "https://lists.fedoraproject.org/archives/list/package-announce%40lists.fedoraproject.org/message/VJAOGY2T2QJFJDTGE7PPY3MZ4XWBDUU6" );
	script_tag( name: "solution_type", value: "VendorFix" );
	script_category( ACT_GATHER_INFO );
	script_copyright( "Copyright (C) 2017 Greenbone Networks GmbH" );
	script_family( "Fedora Local Security Checks" );
	script_dependencies( "gather-package-list.sc" );
	script_mandatory_keys( "ssh/login/fedora", "ssh/login/rpms",  "ssh/login/release=FC27" );
	exit( 0 );
}
require("revisions-lib.inc.sc");
require("pkg-lib-rpm.inc.sc");
release = rpm_get_ssh_release();
if(!release){
	exit( 0 );
}
res = "";
if(release == "FC27"){
	if(( res = isrpmvuln( pkg: "sensible-utils", rpm: "sensible-utils~0.0.11~1.fc27", rls: "FC27" ) ) != NULL){
		security_message( data: res );
		exit( 0 );
	}
	if(__pkg_match){
		exit( 99 );
	}
	exit( 0 );
}

